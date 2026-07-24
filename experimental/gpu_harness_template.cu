/*
 * gpu_harness_template.cu
 * 
 * WinAFL - Tier 2 GPU Fuzzing Template
 * Original AFL code written by Michal Zalewski <lcamtuf@google.com>
 * Windows fork written and maintained by Ivan Fratric <ifratric@google.com>
 * CUDA GPU acceleration written and contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)
 * Copyright 2016, 2026 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * 
 * GOAL:
 *   Instead of running the target function on the CPU (one by one), we run thousands 
 *   of instances of the target function in parallel on the GPU.
 * 
 * REQUIREMENTS:
 *   1. The target logic must be "pure" (no syscalls, no file I/O, no network).
 *   2. The target must be recompilable with `nvcc`.
 * 
 * USAGE:
 *   1. Copy your target function logic into `target_func_gpu`.
 *   2. Use this as a standalone high-speed fuzzer interacting with AFL via shared mem or pipes.
 */

#include <cuda_runtime.h>
#include <stdio.h>

#define MAX_INPUT_LEN 1024
#define MAP_SIZE_BITS 65536
#define MAP_SIZE_INTS (MAP_SIZE_BITS / 32)

// --------------------------------------------------------------------------------
// USER TARGET LOGIC HERE
// --------------------------------------------------------------------------------

__device__ void record_cov(unsigned int* shared_map, u32 edge_id) {
    // Highly efficient atomic OR into block-level shared memory
    atomicOr(&shared_map[edge_id / 32], 1 << (edge_id % 32));
}

// Example generic target function: parses a "packet"
__device__ void target_func_gpu(u8* buf, int len, unsigned int* shared_map, u32* crash_flag) {
    // Simple state machine or parser logic
    if (len < 4) return;
    
    // Check magic bytes
    if (buf[0] == 'P' && buf[1] == 'K') {
        record_cov(shared_map, 0);
        
        if (buf[2] == 0x01) {
             record_cov(shared_map, 1);
             
             if (buf[3] == 0xFF) {
                 // CRASH! (simulated)
                 atomicExch(crash_flag, 1); // Report crash immediately
             }
        }
    }
}

// --------------------------------------------------------------------------------
// KERNEL
// --------------------------------------------------------------------------------

__global__ void fuzz_kernel(u8* inputs, int* lengths, u32 batch_size, unsigned int* global_coverage_map, u32* global_crash_flag) {
    // Allocate highly efficient shared memory for the coverage map
    // All threads in the block will contribute to this shared map before persisting to VRAM
    __shared__ unsigned int shared_bitmap[MAP_SIZE_INTS];

    // Initialize shared bitmap to 0
    for(int i = threadIdx.x; i < MAP_SIZE_INTS; i += blockDim.x) {
        shared_bitmap[i] = 0;
    }
    __syncthreads();

    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < batch_size) {
        u8* my_input = &inputs[idx * MAX_INPUT_LEN];
        int my_len = lengths[idx];

        target_func_gpu(my_input, my_len, shared_bitmap, global_crash_flag);
    }
    
    __syncthreads();

    // Merge block's shared bitmap into the global device bitmap
    for(int i = threadIdx.x; i < MAP_SIZE_INTS; i += blockDim.x) {
        if (shared_bitmap[i] != 0) {
            atomicOr(&global_coverage_map[i], shared_bitmap[i]);
        }
    }
}

// --------------------------------------------------------------------------------
// HOST RUNNER (Example)
// --------------------------------------------------------------------------------

int main() {
    printf("[GPU Fuzzer] This is a template. Integrate this logic into your specific harness.\n");
    return 0;
}
