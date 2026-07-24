/*
   WinAFL - CUDA GPU Acceleration Header
   -------------------------------------

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

#ifndef AFL_FUZZ_GPU_H
#define AFL_FUZZ_GPU_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize GPU (allocating pinned memory and streams).
int gpu_init();

// Check if GPU is ready/available.
int gpu_is_available();

// Launch mutation kernel asynchronously.
// buffer_id should be 0 or 1 for double buffering.
int gpu_mutate_batch_async(int buffer_id, u8* seed, u32 seed_len, u32 batch_size);

// Synchronize a specific buffer's stream, ensuring GPU to Host memory transfer is finished.
int gpu_sync(int buffer_id);

// Retrieve a specific mutated testcase from the batch (reads from pinned host memory).
size_t gpu_get_mutation(int buffer_id, u32 index, u8* out_buf, u32 max_len);

// Release all GPU resources (VRAM, streams, curand states).
void gpu_cleanup();

#ifdef __cplusplus
}
#endif

#endif
