/*
   WinAFL - CUDA GPU Mutation Offloading Core Implementation
   --------------------------------------------------------

   Original AFL code written by Michal Zalewski <lcamtuf@google.com>
   Windows fork written and maintained by Ivan Fratric <ifratric@google.com>
   CUDA GPU acceleration written and contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)

   Copyright 2016, 2026 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#include <cuda_runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curand_kernel.h>

#include "afl-fuzz-gpu.h"

typedef struct {
    u8* d_seed;
    u8* d_output;
    u8* h_seed;
    u8* h_output;
    cudaStream_t stream;
    u32 current_seed_len;
    u32 current_batch_size;
} GPUBatch;

typedef struct {
    int initialized;
    size_t max_file_sz;
    size_t batch_capacity;
    GPUBatch buffers[2];
    curandState* d_curand_states[2];
} GPUContext;

static GPUContext g_ctx = {0};

__global__ void setup_kernel(curandState* state, unsigned long seed, int max_threads) {
    int id = threadIdx.x + blockIdx.x * blockDim.x;
    if (id < max_threads) {
        curand_init(seed, id, 0, &state[id]);
    }
}

#define GET_BYTE(out, batch_idx, batch_sz, byte_idx) (out[(byte_idx) * (batch_sz) + (batch_idx)])

// Simple mutation kernel
__global__ void mutate_kernel(u8* seed, u32 seed_len, u8* output_batch, size_t max_file_sz, u32 batch_size, curandState* global_state) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= batch_size) return;

    curandState local_state = global_state[idx];
    
    // Copy seed directly to transposed layout
    for (int i = 0; i < seed_len; i++) {
        GET_BYTE(output_batch, idx, batch_size, i) = seed[i];
    }
    
    // Mutate
    // 1. Bit flip
    int num_flips = (curand(&local_state) % 4) + 1;
    for(int i=0; i<num_flips; i++) {
        u32 flip_idx = curand(&local_state) % seed_len;
        u8 flip_val = 1 << (curand(&local_state) % 8);
        GET_BYTE(output_batch, idx, batch_size, flip_idx) ^= flip_val;
    }
    
    // 2. Arithmetic (add/sub)
    if (curand(&local_state) % 3 == 0) {
        u32 arith_idx = curand(&local_state) % seed_len;
        u8 val = (curand(&local_state) % 35) + 1;
        if (curand(&local_state) % 2 == 0)
             GET_BYTE(output_batch, idx, batch_size, arith_idx) += val;
        else
             GET_BYTE(output_batch, idx, batch_size, arith_idx) -= val;
    }

    // 3. Block deletion
    if (seed_len > 4 && curand(&local_state) % 5 == 0) {
        u32 del_len = (curand(&local_state) % (seed_len / 2)) + 1;
        u32 del_pos = curand(&local_state) % (seed_len - del_len);
        for (int i = del_pos; i < seed_len - del_len; i++) {
            GET_BYTE(output_batch, idx, batch_size, i) = GET_BYTE(output_batch, idx, batch_size, i + del_len);
        }
        for(int i = seed_len - del_len; i < seed_len; i++) {
             GET_BYTE(output_batch, idx, batch_size, i) = 0;
        }
    }
    
    // 4. Byte overlap
    if (seed_len > 2 && curand(&local_state) % 4 == 0) {
        u32 copy_from = curand(&local_state) % seed_len;
        u32 copy_to = curand(&local_state) % seed_len;
        u32 copy_len = (curand(&local_state) % 4) + 1;
        if (copy_from + copy_len <= seed_len && copy_to + copy_len <= seed_len) {
            for(int i=0; i<copy_len; i++) {
                GET_BYTE(output_batch, idx, batch_size, copy_to + i) = GET_BYTE(output_batch, idx, batch_size, copy_from + i);
            }
        }
    }

    global_state[idx] = local_state;
}

// Secure GPU API Error macro implementation
#define GPU_SAFE(call) do {                    \
    cudaError_t err = (call);                  \
    if(err != cudaSuccess) {                   \
      fprintf(stderr, "[GPU] CUDA FAIL: %s\n", \
              cudaGetErrorString(err));        \
      return 1;                                \
    }                                          \
} while(0)

extern "C" int gpu_init() {
    if (g_ctx.initialized) return 0;

    int count;
    cudaError_t err = cudaGetDeviceCount(&count);
    if (err != cudaSuccess || count == 0) {
        fprintf(stderr, "[GPU] No CUDA devices.\n");
        return 1;
    }

    int gpu_device = 0;
    char* gpu_device_env = getenv("AFL_GPU_DEVICE");
    if (gpu_device_env) {
        int parsed_device = atoi(gpu_device_env);
        if (parsed_device >= 0 && parsed_device < count) {
            gpu_device = parsed_device;
        }
    }

    GPU_SAFE(cudaSetDevice(gpu_device));

    // Default max file size for GPU buffers. This can be overridden.
    size_t seed_buf_sz = 64 * 1024; // 64KB default (much safer pinned-memory footprint)
    char* max_file_env = getenv("AFL_GPU_MAX_FILE_SIZE");
    if (max_file_env) {
        size_t parsed_max = (size_t)atoll(max_file_env);
        if (parsed_max >= 4096) {
            seed_buf_sz = parsed_max;
        }
    }
    g_ctx.max_file_sz = seed_buf_sz;

    // Dynamic batching by VRAM with an explicit pinned-memory budget cap.
    cudaDeviceProp prop;
    GPU_SAFE(cudaGetDeviceProperties(&prop, gpu_device));
    size_t vram = prop.totalGlobalMem;
    size_t dyn_batch = (size_t)(0.25 * vram) / (2 * g_ctx.max_file_sz + 256);

    size_t pinned_budget_mb = 256;
    char* pinned_budget_env = getenv("AFL_GPU_PINNED_MB");
    if (pinned_budget_env) {
        size_t parsed_budget = (size_t)atoll(pinned_budget_env);
        if (parsed_budget >= 32) {
            pinned_budget_mb = parsed_budget;
        }
    }
    size_t capacity_by_budget = ((pinned_budget_mb * 1024ULL * 1024ULL) / g_ctx.max_file_sz);

    g_ctx.batch_capacity = dyn_batch;
    if (capacity_by_budget > 0 && g_ctx.batch_capacity > capacity_by_budget) {
        g_ctx.batch_capacity = capacity_by_budget;
    }
    if (g_ctx.batch_capacity < 1) g_ctx.batch_capacity = 1;

    // Optional explicit init capacity cap.
    char* init_cap_env = getenv("AFL_GPU_INIT_CAPACITY");
    if (init_cap_env) {
        size_t parsed_cap = (size_t)atoll(init_cap_env);
        if (parsed_cap >= 1 && g_ctx.batch_capacity > parsed_cap) {
            g_ctx.batch_capacity = parsed_cap;
        }
    }

    // Final hard safety cap.
    if (g_ctx.batch_capacity > 131072) g_ctx.batch_capacity = 131072;

    size_t total_sz = g_ctx.max_file_sz * g_ctx.batch_capacity;

    for (int i = 0; i < 2; i++) {
        // Allocate streams
        GPU_SAFE(cudaStreamCreate(&g_ctx.buffers[i].stream));

        // Allocate device memory
        GPU_SAFE(cudaMalloc(&g_ctx.buffers[i].d_seed, seed_buf_sz));
        GPU_SAFE(cudaMalloc(&g_ctx.buffers[i].d_output, total_sz));

        // Allocate pinned host memory
        GPU_SAFE(cudaMallocHost(&g_ctx.buffers[i].h_seed, seed_buf_sz));
        GPU_SAFE(cudaMallocHost(&g_ctx.buffers[i].h_output, total_sz));
    }

    g_ctx.initialized = 1;

    // Allocate curand states per buffer to avoid race conditions
    for (int i = 0; i < 2; i++) {
        GPU_SAFE(cudaMalloc(&g_ctx.d_curand_states[i], g_ctx.batch_capacity * sizeof(curandState)));

        int threads = 256;
        int blocks = (g_ctx.batch_capacity + threads - 1) / threads;
        setup_kernel<<<blocks, threads, 0, g_ctx.buffers[i].stream>>>(g_ctx.d_curand_states[i], time(NULL) + i, g_ctx.batch_capacity);
    }
    GPU_SAFE(cudaDeviceSynchronize());

    fprintf(stderr, "[GPU] Initialized Double Buffering & CuRand.\n[GPU] Device: %d\n[GPU] Hardware: %s (VRAM: %zu MB)\n[GPU] Max seed size: %zu bytes\n[GPU] Dynamic Batch Capacity: %zu per buffer\n", 
            gpu_device, prop.name, vram / (1024 * 1024), g_ctx.max_file_sz, g_ctx.batch_capacity);
    return 0;
}

extern "C" int gpu_is_available() {
    return g_ctx.initialized;
}

extern "C" int gpu_mutate_batch_async(int buffer_id, u8* seed, u32 seed_len, u32 batch_size) {
    if (!g_ctx.initialized || buffer_id < 0 || buffer_id > 1) return 1;
    if (seed_len == 0 || seed_len > g_ctx.max_file_sz) {
        fprintf(stderr, "[GPU] Seed too large for configured GPU buffer (%u > %zu). Increase AFL_GPU_MAX_FILE_SIZE.\n", seed_len, g_ctx.max_file_sz);
        return 1;
    }
    if (batch_size > g_ctx.batch_capacity) batch_size = g_ctx.batch_capacity;

    GPUBatch* b = &g_ctx.buffers[buffer_id];
    b->current_seed_len = seed_len;
    b->current_batch_size = batch_size;

    // Copy seed to pinned host memory (fast CPU copy)
    for (size_t i = 0; i < seed_len; ++i) {
        b->h_seed[i] = seed[i];
    }

    // Async copy seed to device
    GPU_SAFE(cudaMemcpyAsync(b->d_seed, b->h_seed, seed_len, cudaMemcpyHostToDevice, b->stream));

    // Launch kernel async with per-buffer curand states
    int threads = 256;
    int blocks = (batch_size + threads - 1) / threads;
    mutate_kernel<<<blocks, threads, 0, b->stream>>>(b->d_seed, seed_len, b->d_output, g_ctx.max_file_sz, batch_size, g_ctx.d_curand_states[buffer_id]);

    // Async copy only the bytes we actually need (transposed layout: seed_len * batch_size)
    size_t copy_size = (size_t)seed_len * batch_size;
    GPU_SAFE(cudaMemcpyAsync(b->h_output, b->d_output, copy_size, cudaMemcpyDeviceToHost, b->stream));
    
    cudaError_t err = cudaGetLastError();
    if(err != cudaSuccess) {
        fprintf(stderr, "[GPU] Kernel Launch FAIL: %s\n", cudaGetErrorString(err));
        return 1;
    }
    return 0;
}

extern "C" int gpu_sync(int buffer_id) {
    if (!g_ctx.initialized || buffer_id < 0 || buffer_id > 1) return 1;
    GPUBatch* b = &g_ctx.buffers[buffer_id];
    GPU_SAFE(cudaStreamSynchronize(b->stream));
    return 0;
}

extern "C" size_t gpu_get_mutation(int buffer_id, u32 index, u8* out_buf, u32 max_len) {
    if (!g_ctx.initialized || buffer_id < 0 || buffer_id > 1) return 0;
    GPUBatch* b = &g_ctx.buffers[buffer_id];
    
    // We assume gpu_sync(buffer_id) has been called beforehand.
    size_t len_to_copy = b->current_seed_len;
    if (len_to_copy > max_len) len_to_copy = max_len;

    u8* host_ptr = b->h_output;
    for (size_t i = 0; i < len_to_copy; ++i) {
        out_buf[i] = host_ptr[i * b->current_batch_size + index];
    }
    
    return len_to_copy;
}

extern "C" void gpu_cleanup() {
    if (!g_ctx.initialized) return;

    for (int i = 0; i < 2; i++) {
        if (g_ctx.buffers[i].d_seed) cudaFree(g_ctx.buffers[i].d_seed);
        if (g_ctx.buffers[i].d_output) cudaFree(g_ctx.buffers[i].d_output);
        if (g_ctx.buffers[i].h_seed) cudaFreeHost(g_ctx.buffers[i].h_seed);
        if (g_ctx.buffers[i].h_output) cudaFreeHost(g_ctx.buffers[i].h_output);
        cudaStreamDestroy(g_ctx.buffers[i].stream);
        if (g_ctx.d_curand_states[i]) cudaFree(g_ctx.d_curand_states[i]);
    }

    g_ctx.initialized = 0;
    fprintf(stderr, "[GPU] Resources cleaned up.\n");
}
