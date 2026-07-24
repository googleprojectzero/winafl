# The Complete Fuzzer's Guide to GPU-Accelerated WinAFL

*Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)*

This guide provides a comprehensive, end-to-end walkthrough on how to conduct a professional fuzzing campaign using this GPU-accelerated fork of WinAFL. It covers everything from selecting a vulnerable target to weaponizing the crashes you find.

---

## 1. Finding a Suitable Target

Not all applications are good candidates for fuzzing. WinAFL relies on repeatedly feeding mutated data into a target function. 

### What makes a good target?
- **File Parsers:** Applications that take complex, structured files as input (e.g., PDF readers, Image viewers, Video players, Office suites, CAD software).
- **Network Services:** Custom protocols, HTTP servers, or clients that process external data packets.
- **Stateless/Determinism:** The target function should ideally produce the same output/behavior given the same input, without relying heavily on external state (like databases or internet requests).
- **Speed:** The target function needs to execute quickly. The faster the initialization and teardown, the more executions per second (execs/sec) WinAFL can achieve.

### Finding the Attack Surface
Look for applications handling untrusted user input:
1.  **Libraries:** Often the best targets. Look for `dll` files responsible for parsing (e.g., `libpng.dll`, `avcodec.dll`).
2.  **Command Line Utilities:** Tools that process a file passed via argument (e.g., `magick.exe image.jpg new.png`).
3.  **GUI Applications:** You will need to find the specific function within the GUI app that handles the "File -> Open" or parsing logic.

---

## 2. Harnessing the Target

WinAFL uses **DynamoRIO** (or TinyInst/Intel PT) to instrument closed-source Windows binaries dynamically. To do this, WinAFL needs to know exactly *where* to start fuzzing.

### Identifying the Target Function
You cannot simply fuzz `main()`. You need to isolate the function that actually parses the data.
1.  Open the target binary or DLL in a disassembler like **IDA Pro**, **Ghidra**, or **Binary Ninja**.
2.  Trace the execution flow from the point a file is opened (e.g., `CreateFileW`, `fopen`) to where the data is actually processed.
3.  Identify the function offset (e.g., `0x12A40`).

### Requirements for the Target Function:
- It must open the input file.
- It must parse the file data.
- It must close the file handle (crucial, otherwise WinAFL cannot overwrite the file for the next mutation).
- It must return normally (it cannot call `ExitProcess`).

### Verifying the Harness
Before fuzzing, test your target function using DynamoRIO's standalone tool to ensure it executes correctly and is caught by the instrumentation:
```cmd
path\to\DynamoRIO\bin64\drrun.exe -c winafl.dll -debug -target_module target.exe -target_offset 0x12A40 -fuzz_iterations 10 -nargs 2 -- target.exe input.txt
```
Check the generated `afl.log` to ensure it successfully captured the iterations without crashing prematurely.

---

## 3. Preparing the Seed Corpus

The quality of your initial inputs (seeds) determines the success of the campaign. WinAFL uses these initial files and mutates them on the GPU to discover new code paths.

### Building the Corpus
1.  Gather valid files of the target format (e.g., 50 different `.pdf` files).
2.  Ensure they are small. Fuzzing a 10MB PDF is incredibly slow. Aim for files under 10KB.
3.  Ensure they hit different features of the parser (e.g., one PDF with images, one with an encrypted stream, one with forms).

### Minimizing the Corpus
Running WinAFL with redundant seeds wastes time. Use `afl-tmin` to minimize the size of individual files, and then use `winafl-cmin.py` to remove seeds that trigger the exact same code paths.

To minimize a single file:
```cmd
bin\Release\afl-tmin.exe -D \path\to\DynamoRIO\bin64 -t 1000 -- target.exe @@
```

---

## 4. Running the GPU-Accelerated Fuzzer

With your target harnessed and your seeds ready (`in/` folder), it's time to unleash the GPU.

The `-G` (or `/gpu`) flag tells WinAFL to offload the heavy "Havoc" mutation stage to the NVIDIA CUDA architecture, multiplying your mutation throughput.

### The Launch Command
```cmd
bin\Release\afl-fuzz.exe -G -i in_dir -o out_dir -t 2000 -D \path\to\DynamoRIO\bin64 -w bin\Release\winafl.dll -target_module target.exe -target_offset 0x12A40 -coverage_module target.exe -fuzz_iterations 5000 -- target.exe @@
```

### Understanding the Flags:
- `-G` (or `/gpu`): Enables the high-throughput VRAM mutation engine.
- `-i` / `-o`: Input seed directory and output findings directory.
- `-t 2000`: Timeout in milliseconds. If the target hangs for 2 seconds, it counts as a crash/hang.
- `-target_module` / `-target_offset`: The exact DLL/EXE and function address you identified in step 2.
- `-coverage_module`: The specific module you want to record code coverage for (keeps instrumentation fast).
- `@@`: WinAFL replaces this with the path to the mutated file it generates for each execution.

### Monitoring the Campaign
Watch the `afl-fuzz` UI. 
- **exec speed**: This is your executions per second. The higher, the better. (Aim for >50 exec/s for heavy targets, >1000 for light targets).
- **uniq crashes**: The holy grail. If this number increases, WinAFL found an input that caused a memory access violation or fatal exception.
- **gpu batches**: Indicates successful offloading to the CUDA streams.

---

## 5. Triaging Crashes

When WinAFL finds a crash, it saves the mutated input file that caused it into the `out_dir/crashes/` folder.

1.  **Reproduce:** Take a crashing file and run it manually against the target application to ensure it consistently crashes.
2.  **Analyze the Exception:** Open the target in a native debugger like **WinDbg** or **x64dbg**.
3.  Run the application with the crashing file:
    ```cmd
    windbg.exe target.exe out_dir\crashes\id_000000_...
    ```
4.  When the debugger catches the exception, use commands like `!analyze -v` in WinDbg.

### Identifying the Bug Class
You are looking for specific violations:
- **Access Violation (0xC0000005):** The program tried to read or write to unallocated memory.
    - *Read Access Violation:* Often an Out-Of-Bounds (OOB) Read. Can lead to Information Leakage.
    - *Write Access Violation:* Often a Buffer Overflow, Use-After-Free (UAF), or Type Confusion. These are prime candidates for Remote Code Execution (RCE).
- **Stack Exhaustion / Recursion:** Usually Denial of Service (DoS), harder to exploit for RCE.
- **Divide by Zero:** Usually DoS.

---

## 6. Exploitation (Weaponization)

Once you've triaged a Write Access Violation or an exploitable Read, you transition from Fuzzing to Exploit Development.

1.  **Root Cause Analysis:** Use your disassembler (IDA/Ghidra) alongside WinDbg. Look at the assembly instructions surrounding the crash. *Why* did it crash? Was a size header parsed incorrectly? Did an integer overflow occur during allocation (`malloc(size * count)`)?
2.  **Controlling the Instruction Pointer (RIP/EIP):** If it's a buffer overflow, can you overwrite the return address on the stack, or a function pointer in the heap? You need to trace the exact offset in your mutated file that corresponds to the overwritten memory.
3.  **Bypassing Mitigations:** Modern Windows binaries have defenses:
    - **ASLR (Address Space Layout Randomization):** You will likely need an Information Leak (an OOB Read bug) to find the base addresses of `ntdll.dll` or your target module to bypass ASLR.
    - **DEP (Data Execution Prevention):** You cannot just execute shellcode on the stack. You must use **ROP (Return-Oriented Programming)** to chain together existing snippets of code ("gadgets") to call functions like `VirtualProtect` or `WinExec`.
    - **CFG (Control Flow Guard):** If enabled, you must find ways around indirect call validation.
4.  **The Final Exploit:** You write a Python script that perfectly crafts a malicious file (e.g., a `.pdf`). It triggers the integer overflow, overwrites a vtable pointer, uses a ROP chain to bypass DEP, and executes your custom shellcode (like popping `calc.exe` or opening a reverse shell).
