# Ghidra MCP Integration Guide

*Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)*

This guide provides end-to-end instructions for connecting **WinAFL AI Agents** to **Ghidra** via Model Context Protocol (MCP) servers.

While our Python utilities (like `winafl-target-finder.py`) use `dumpbin.exe` out of the box to quickly discover parsing functions, things get a lot more powerful when you plug **Ghidra** into the pipeline. 

By running Ghidra v11 with an active Model Context Protocol (MCP) extension, you upgrade the automated script from a basic "offset finder" into a deep-learning reverse engineer capable of understanding code context.

Here is the setup, how to use it, and exactly what it does for your fuzzing campaigns.

---

## 1. Setup & Installation

### The Prerequisites
* **Ghidra v11+**: Ensure you have a recent version of Ghidra running.
* **Python 3.6+**: You must have Python installed and added to your system PATH.
* **Ghidra Bridge / MCP Server**: You need an RPC bridge running inside Ghidra that allows external Python scripts to query its decompiler.
    * **Install the Python package**:
      1. Open your Command Prompt (`cmd.exe`).
      2. Verify Python is working by typing `python --version`.
      3. Type: `pip install ghidra_bridge` and press Enter.
      4. Wait for the "Successfully installed ghidra_bridge..." message.
    * **Install the Ghidra Server Plugin:** 
      1. Open your target binary in the Ghidra CodeBrowser.
      2. If you are using the `bridge_mcp_hydra.py` MCP extension, it communicates with Ghidra's REST API. You must install the corresponding Ghidra server plugin (usually an extension zip file) into Ghidra and enable it.
      3. Start the plugin server within Ghidra so it listens on the default port (8192).
    * **Run the MCP Python Bridge:**
      1. Open your Command Prompt (`cmd.exe`).
      2. Navigate to where you saved the bridge script: `cd d:\hacking\tools`
      3. Run the script: `python bridge_mcp_hydra.py`
      4. The script will automatically discover your running Ghidra instance on port 8192 and provide the MCP interface.

### The Connection
When `winafl-harness-builder.py` starts up, it automatically attempts to import `ghidra_bridge`.
If the import succeeds, the script is now in **Enhanced Ghidra Mode**.

To use this mode, your Ghidra client **must be open**, the target binary must be loaded/analyzed in the CodeBrowser, and the RPC server script (e.g., `GhidraBridgeServer.py` or the MCP server) must be running.

---

## 2. How to Use It in the Pipeline

Using Ghidra doesn't change *how* you use the Python scripts; it just makes them dramatically smarter.

Normally, you would use dumpbin to find an offset, and then tell the compiler to build a generic harness:
```cmd
python winafl-harness-builder.py generate target.dll --offset 0x41040
```

**With Ghidra Running:**
You simply include Ghidra in your workflow like normal, it happens automatically behind the scenes!
Here is the exact step-by-step flow:
1. Double-click your target `.dll` or `.exe` and load it into your Ghidra Project.
2. Open it in the **CodeBrowser** and let auto-analysis finish (the progress bar in the bottom right).
3. Ensure you have started the `ghidra_bridge_server.py` script from the Script Manager as described in Section 1.
4. Leave Ghidra open on your screen.
5. In your Command Prompt window, run the harness generator tool just like you would without Ghidra:
    ```cmd
    python winafl-harness-builder.py generate target.dll --offset 0x41040
    ```
6. The python script will notice the Bridge Server is listening, log "Ghidra Bridge connected", and bypass dumpbin entirely to extract its data directly from Ghidra!

---

## 3. What Does Ghidra Actually Do?

When Ghidra is connected to the harness builder, it performs **High-Fidelity Analysis** rather than simple assembly parsing. Here is exactly what the MCP integration unlocks:

### A. Perfectly Accurate Function Signatures
Without Ghidra, the script guesses how many arguments a function takes by counting assembly registers. 
**With Ghidra**, the script queries the exact decompiled signature.
* *Example Dumpbin:* `typedef int (*TargetFunc)(void*, void*);`
* *Example Ghidra:* `typedef HRESULT (WINAPI *TargetFunc)(HANDLE hFile, LPCWSTR pwszFormat, DWORD dwFlags);`

This means the generated C code in `harness.c` is guaranteed to compile and successfully pass data into the target without crashing the stack.

### B. Auto-Detecting the Harness Style
WinAFL harnesses need to wrap the target function differently depending on what the target expects.
* **File Parser Style:** If Ghidra detects the target's arguments are `const char* filename` or `LPCWSTR path`, the script automatically generates a harness that passes the mutated fuzzer file path.
* **Stream Style:** If Ghidra sees the target asks for a `HANDLE` or `FILE*`, the script generates a harness that *opens the file for you*, passes the handle, and strictly closes it afterward (crucial to avoid WinAFL handle exhaustion).
* **Buffer Style:** If Ghidra sees `uint8_t* buffer` and `size_t length`, the script automatically builds a harness that allocates memory, reads the mutated file into RAM, and passes the buffer.

### C. Deep Behavioral Call Graphs
Instead of scanning 50 lines of blind assembly for a `CreateFileA` call, Ghidra builds a complete call graph.
The script queries Ghidra to see if the target function *eventually* calls a file read or memory allocation downstream. 
It analyzes the **Decompiled C Code** directly for high-risk behaviors:
* Does it allocate memory and fail to free it? (The script warns you to add cleanup logic to the harness).
* Does it call `ExitProcess` or `abort`? (The script throws a fatal error because WinAFL cannot fuzz functions that self-terminate the application).

### D. Finding Hidden Parsing Logic
Instead of just looking at exported function names, the MCP extension allows the `winafl-target-finder.py` to scan the internal decompiler logic for string references.
If the script finds a function manipulating strings like `%PDF-1.4` or `PK\x03\x04` (ZIP headers), it immediately flags that offset as a high-value parsing target, even if the function is completely unnamed!

---

## 4. Example: The Ghidra-Powered Workflow

1. You load a massive DLL like `libmedia.dll` into Ghidra and let it auto-analyze.
2. You start the Ghidra RPC Bridge script.
3. You run `python winafl-target-finder.py analyze libmedia.dll` in your terminal.
4. The Python script reaches into Ghidra, scans the decompiler for everything mentioning `fopen`, calculates the exact parameters of the 10 best un-exported parsing functions, and scores them.
5. You pipe the best offset into the harness builder.
6. The harness builder queries Ghidra, realizes the target needs a wide-string path and an initialization flag, writes the C code, compiles it, and launches the fuzzer.

By combining the speed of the CLI Python tools with the brain of Ghidra, you automate the entire reverse engineering and harnessing bottleneck of Windows fuzzing!
