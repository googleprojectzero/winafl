# WinAFL CUDA GPU Acceleration - Technical Architecture & Change Summary

**Author:** Elias Ibrahim `<elie.ibrahim@gmail.com>`  
**Date:** February 2026  
**Target Repository:** `google/winafl`  
**Feature Title:** Hardware-Accelerated GPU Havoc Mutation Engine (Tier 1 & Tier 2)  

---

## 1. Executive Summary & Rationale

WinAFL traditional fuzzing spends significant CPU cycles sequentially generating mutations in the `havoc_stage` loop (`fuzz_one`) on a single CPU core before invoking target execution.

This contribution introduces **NVIDIA CUDA GPU Acceleration** to WinAFL:
- **Tier 1 (GPU Havoc Mutator):** Seed mutations (bitflips, byte additions/subtractions, block mutations, dictionary splicing) are offloaded to thousands of parallel CUDA threads on the GPU.
- **Asynchronous Double-Buffering:** Uses DMA page-locked host memory (`cudaMallocHost`) and dual CUDA streams (`cudaMemcpyAsync`) so the CPU evaluates testcases from Batch $N$ while the GPU concurrently mutates Batch $N+1$.
- **Hardware Entropy (`cuRand`):** Integrates per-thread CUDA `curandState` generators for lock-free parallel entropy.
- **Coalesced VRAM Access:** Transposes the global mutation matrix to guarantee 100% warp memory coalescing.
- **Tier 2 (GPU Target Execution Harness Template):** Included in `experimental/gpu_harness_template.cu` for pure-logic targets running entirely in VRAM with `atomicOr()` shared memory coverage.

---

## 2. Architecture & Performance Pipeline

### Asynchronous Memory Pipeline (Double Buffering)
```
          CPU Execution Loop (Batch N)
          ┌────────────────────────────────────────────────────────┐
          │  common_fuzz_stuff() -> Target Execution (DynamoRIO)  │
          └────────────────────────────────────────────────────────┘
                                     │
                             (Concurrent Execution)
                                     ▼
          GPU CUDA Pipeline (Batch N+1)
          ┌────────────────────────────────────────────────────────┐
          │  1. cudaMemcpyAsync (Host Pinned -> Device VRAM)      │
          │  2. mutation_kernel<<<blocks, threads, 0, stream>>>   │
          │  3. cudaMemcpyAsync (Device VRAM -> Host Pinned)      │
          └────────────────────────────────────────────────────────┘
```

### Key Optimizations Implemented:
1. **DMA Page-Locked Memory (`cudaMallocHost`):** Prevents double-bouncing through page-table lookups, achieving maximum PCIe bus throughput.
2. **CUDA Streams (`cudaStream_t`):** Dual stream execution allows overlapping host CPU target evaluation with GPU VRAM mutation generation.
3. **Warp Memory Coalescing:** Memory is structured as `[mutation_index * batch_capacity + thread_id]` so adjacent threads write to adjacent bytes in VRAM.
4. **Singleton Manager (`afl-fuzz-gpu.cu`):** Encapsulates all CUDA context and stream allocations cleanly without cluttering existing AFL C structures.
5. **Graceful Degradation:** If compiled without CUDA support or executed on hardware without an NVIDIA GPU, WinAFL falls back to standard CPU fuzzing without breaking existing DynamoRIO, Intel PT, or TinyInst workflows.

---

## 3. Command Line & Configuration Options

### Command Line Flags
| Flag | Short | Description |
| :--- | :--- | :--- |
| `-G` | `-G` / `/gpu` | Enables GPU mutation offloading in `afl-fuzz.exe`. |

*Note: For backward compatibility with scripts, `/gpu` and `-gpu` are automatically mapped to `-G` internally.*

### Environment Variables
| Variable | Default | Description |
| :--- | :--- | :--- |
| `AFL_GPU_BATCH_SIZE` | `10000` | Sets the number of parallel GPU thread allocations per batch buffer. |

---

## 4. Itemized File Manifest

### Added Core CUDA Feature Files
- **`afl-fuzz-gpu.cu`**: CUDA device kernel implementations, double-buffer allocation, `cuRand` initialization, memory transposition.
- **`afl-fuzz-gpu.h`**: Header declaring C interface (`gpu_init()`, `gpu_mutate_batch_async()`, `gpu_sync()`, `gpu_get_mutation()`).
- **`experimental/gpu_harness_template.cu`**: Tier 2 GPU-native target execution template with `atomicOr()` shared coverage bitmap.

### Added Documentation & Tooling
- **`SETUP_AND_RUN.md`**: Environment setup guide for CUDA 11+/12+/13+, CMake 3.18+, and Visual Studio 2019/2022.
- **`FUZZING_GUIDE.md`**: End-to-end fuzzing campaign guide.
- **`winafl-target-finder.py`**: Automated target binary scanning & harness launch configuration generator.
- **`winafl-harness-builder.py`**: Automated C/C++ fuzzer harness code generator.
- **`ghidra_bridge.py`**: Protocol-agnostic Ghidra MCP server bridge client.
- **`GHIDRA_INTEGRATION.md`** & **`GHIDRA_MCP_INTEGRATION_GUIDE.md`**: Ghidra integration guides.
- **`WIN_AFL_ZERO_TO_HERO_GUIDE.md`**: Fuzzing campaign guide.

### Modified Files in Upstream WinAFL
- **`CMakeLists.txt`**: Upgraded CMake to 3.18+, added `check_language(CUDA)` & `enable_language(CUDA)` check, defined `-DHAVE_CUDA`, and conditionally appended `afl-fuzz-gpu.cu` to `AFL_FUZZ_SOURCES`.
- **`afl-fuzz.c`**: Added `-G` / `/gpu` CLI flags, `AFL_GPU_BATCH_SIZE` env var, async havoc stage loop in `fuzz_one()`, and GPU status UI (`gpu batches`, `gpu execs`).
- **`README.md`**: Added GPU Acceleration usage section, flag details, and tool descriptions.
- **`ChangeLog`**: Added Version 1.17 (Feb 2026) release entry with author attribution.

---

## 5. Build & Verification Instructions

### Requirements
- Windows 10/11 x64
- Visual Studio 2019 or 2022 (Desktop C++ Workload)
- NVIDIA CUDA Toolkit 11.0 or higher
- CMake 3.18+

### Build Commands
```cmd
cmake -G "Visual Studio 17 2022" -A x64 .
cmake --build . --config Release
```

### Execution Example
```cmd
bin\Release\afl-fuzz.exe -G -i in -o out -t 1000 -D C:\path\to\DynamoRIO\bin64 -- target.exe @@
```
