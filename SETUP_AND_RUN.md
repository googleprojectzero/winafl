# WinAFL CUDA - Environment Setup & Execution

*Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)*

Use this guide to set up build tools, IDEs, and run GPU-accelerated WinAFL.

## 1. Prerequisites
- **OS:** Windows 10 or Windows 11 (x64)
- **Compiler:** [Visual Studio 2019 or 2022](https://visualstudio.microsoft.com/) 
  - Ensure you install the **"Desktop development with C++"** workload.
- **CUDA:** [NVIDIA CUDA Toolkit 11.0+](https://developer.nvidia.com/cuda-downloads) (e.g. 11.x, 12.x, or 13.x).
- **CMake:** [CMake 3.18+](https://cmake.org/download/) (Ensure it is added to your system `PATH`).

## 2. Setting Up & Building

### Option A: Visual Studio Code (Recommended)
1. Install [VS Code](https://code.visualstudio.com/).
2. Install the **C/C++ Extension Pack** and **CMake Tools** extensions.
3. Open the `winafl` folder in VS Code.
4. VS Code will prompt you to select a "Compiler Kit". Select the 64-bit version (e.g., `Visual Studio Community 2022 Release - amd64`).
5. Open the Command Palette (`Ctrl+Shift+P`), type `CMake: Configure` and select it.
6. Once configured, type `CMake: Build` to build the `afl-fuzz` executable.

### Option B: Visual Studio Command Prompt
1. Open the **"x64 Native Tools Command Prompt for VS 2019/2022"**.
2. Navigate to the `winafl` source directory.
3. Run the following commands to configure and build:
   ```cmd
   cmake -G "Visual Studio 17 2022" -A x64 .
   cmake --build . --config Release
   ```
4. The compiled executables will be written to `bin\Release\`.

## 3. Running the Fuzzer with GPU Acceleration

1. Ensure you have an `in` folder containing at least one valid starting seed (e.g., `in/seed.txt`).
2. Have a target executable compiled and ready (e.g., `bin\Release\test.exe`).
3. Start the fuzzer by appending the `-G` (or `/gpu`) flag:
   ```cmd
   bin\Release\afl-fuzz.exe -G -i in -o out -t 1000 -D C:\path\to\DynamoRIO\bin64 -- bin\Release\test.exe @@
   ```

### Verification
- On launch, the console outputs GPU initialization details:
  ```text
  [*] Initializing GPU acceleration (Batch Size: 10000)...
  [+] GPU initialized successfully
  ```
- On the `afl-fuzz` TUI dashboard, the status line will display:
  `gpu status  : ONLINE  batches=12     execs=120000`
