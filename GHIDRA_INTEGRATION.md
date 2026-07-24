# Ghidra Integration - Setup, Usage & Troubleshooting

*Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)*

Automated reverse engineering for WinAFL harness generation via Ghidra's **REST API**.
This guide covers both **Windows** and **Linux** environments.

> [!IMPORTANT]
> **No AI, no MCP protocol, no extra SDKs.** Our scripts talk directly to Ghidra's
> HTTP REST API using plain Python `urllib`. The Ghidra plugin simply exposes an HTTP
> server on localhost — our tools query it like any other REST API.

---

## Overview

The Ghidra integration adds automated RE analysis to the fuzzing pipeline:

```
┌──────────────┐  HTTP REST API  ┌──────────────┐     ┌──────────────────────────┐
│              │ ◀────────────── │              │     │                          │
│   Ghidra +   │   Decompile     │ ghidra_      │ ──▶ │ winafl-harness-builder   │
│   GhydraMCP  │   Call graph    │ bridge.py    │     │   analyze / generate /   │
│   Plugin     │   XRefs         │  (urllib)     │     │   auto / full            │
│  port 8192   │   Signatures    │              │     │                          │
└──────────────┘                 └──────────────┘     └──────────────────────────┘
         ↑
    No AI. No MCP SDK.
    Just HTTP GET/POST.
```

**Recommended plugin:** [GhydraMCP](https://github.com/starsong-consulting/GhydraMCP) (port 8192)

The bridge also auto-detects [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) (port 8080)
and [GhidrAssistMCP](https://github.com/jtang613/GhidrAssistMCP) (port 8080) if you happen
to have one of those installed instead, but **you only need one**.

---

## Prerequisites

### Windows

1. **Python 3.6+** — `python --version`
2. **Ghidra 11.x** — Download from [https://ghidra-sre.org](https://ghidra-sre.org)
3. **Java JDK 17+** — Required by Ghidra. [Adoptium](https://adoptium.net/)
4. **Visual Studio Build Tools** — For `dumpbin.exe` and `cl.exe` (fallback when Ghidra is unavailable)

### Linux

1. **Python 3.6+** — `python3 --version`
2. **Ghidra 11.x** — Download and extract to e.g. `/opt/ghidra`
3. **Java JDK 17+** — `sudo apt install openjdk-17-jdk` (Debian/Ubuntu) or `sudo dnf install java-17-openjdk` (Fedora)
4. **GCC or Clang** — For compiling generated harnesses

> [!NOTE]
> The `ghidra_bridge.py` module uses only Python stdlib (`urllib`, `json`) — **no pip dependencies required**.

---

## Installation

### Step 1: Install the GhydraMCP Ghidra Plugin

The plugin adds an HTTP REST server to Ghidra. No Python, no AI, no MCP SDK needed on the Ghidra side.

**Download:** [github.com/starsong-consulting/GhydraMCP/releases](https://github.com/starsong-consulting/GhydraMCP/releases)

> [!IMPORTANT]
> The release contains **two zip files**: an outer "Complete" archive and the actual
> plugin zip inside it. You must unpack the outer one first.

**Windows & Linux:**
```bash
# 1. Download the latest release (e.g., GhydraMCP-Complete-2.2.0.zip)
# 2. UNPACK the outer zip — inside you'll find:
#      GhydraMCP-2.2.0.zip    ← This is the actual Ghidra plugin
#      bridge_mcp_ghidra.py   ← MCP bridge (we DON'T need this)
#
# 3. In Ghidra:
#    File → Install Extensions → Click + → Select GhydraMCP-2.2.0.zip
#    (NOT the Complete zip, the inner plugin zip)
# 4. Restart Ghidra
# 5. File → Configure → Developer → Ensure GhydraMCPPlugin is checked
```

If Ghidra **still rejects the zip**, there are two alternative install methods:

```bash
# Alternative A: Manual install (copy to extensions directory)
# 1. Find your Ghidra extensions folder:
#    Windows: %USERPROFILE%\.ghidra\<ghidra_version>\Extensions\
#    Linux:   ~/.ghidra/<ghidra_version>/Extensions/
# 2. Unzip GhydraMCP-2.2.0.zip directly into that folder
# 3. You should have: Extensions/GhydraMCP/lib/GhydraMCP.jar
#                      Extensions/GhydraMCP/extension.properties
# 4. Restart Ghidra

# Alternative B: Build from source (requires Maven + JDK 17+)
git clone https://github.com/starsong-consulting/GhydraMCP.git
cd GhydraMCP
mvn clean package -P plugin-only
# Output: target/GhydraMCP-<version>.zip → install this in Ghidra
```

**Verify it's working:**
```bash
# After opening a binary in Ghidra's CodeBrowser, check the console:
# Click the computer icon in bottom-right of project window → "Open Console"
# Look for: "HydraMCP HTTP server started on port 8192"

# Or test from command line:
curl http://localhost:8192/api/instances          # Linux
python ghidra_bridge.py --test localhost:8192      # Windows or Linux
```

### Step 2: Verify Files Are in Place

Ensure these files are in your WinAFL directory:

```
z:\WinAFL CUDA2\
├── ghidra_bridge.py               # HTTP client for Ghidra REST API
├── winafl-harness-builder.py       # Main harness tool
└── winafl-target-finder.py         # Target discovery tool
```

---

## Usage

### Quick Start — Fully Automated (Ghidra Required)

```bash
# 1. Open your target binary in Ghidra and let auto-analysis complete
# 2. Run:
python winafl-harness-builder.py auto target.dll --ghidra localhost:8192 --out harness/
```

This will:
1. Connect to Ghidra's analysis engine
2. Discover all exported functions + file I/O callers via cross-references
3. Score and rank fuzzing candidates
4. Decompile the top candidates
5. Auto-detect harness style from real parameter types
6. Generate ready-to-compile C harness source files

### Manual Pipeline — With Ghidra Enhancement

```bash
# Analyze a specific function with Ghidra decompilation
python winafl-harness-builder.py analyze target.dll --offset 0x41040 --ghidra localhost:8192

# Generate with Ghidra-derived function signature
python winafl-harness-builder.py generate target.dll --offset 0x41040 --ghidra localhost:8192

# Full pipeline (analyze → generate → validate) with Ghidra
python winafl-harness-builder.py full target.dll --offset 0x41040 --ghidra localhost:8192 --out harness/
```

### Without Ghidra (Fallback to dumpbin)

All commands work without `--ghidra` — they use `dumpbin.exe` for disassembly instead:

```bash
python winafl-harness-builder.py full target.dll --offset 0x41040 --out harness/
```

### Standalone Ghidra Bridge CLI

```bash
# Test connection
python ghidra_bridge.py --test localhost:8192

# List all functions
python ghidra_bridge.py --list-functions localhost:8192

# Filter functions by name
python ghidra_bridge.py --list-functions localhost:8192 --filter CreateBitmap

# Decompile a function
python ghidra_bridge.py --decompile GdipLoadImageFromFile localhost:8192

# Get call graph (depth 3)
python ghidra_bridge.py --callgraph main localhost:8192 --depth 3

# Find cross-references to an address (who calls this function?)
python ghidra_bridge.py --xrefs-to 0x00401000 localhost:8192

# Auto-discover fuzzing targets
python ghidra_bridge.py --find-fuzz-targets localhost:8192

# Get C function signature (for manual typedef)
python ghidra_bridge.py --signature GdipLoadImageFromFile localhost:8192

# Get function variables (parameter names and types)
python ghidra_bridge.py --variables GdipLoadImageFromFile localhost:8192

# JSON output (for scripting/piping)
python ghidra_bridge.py --list-exports localhost:8192 --json
```

---

## What Ghidra Enhancement Provides

| Feature | Without Ghidra (dumpbin) | With Ghidra |
|---------|------------------------|-------------|
| Disassembly | Raw x86/x64 instructions | Full C pseudocode decompilation |
| Arg count | Heuristic from prologue registers | Exact from function prototype |
| Arg types | Unknown (manual typedef needed) | Real types auto-filled in typedef |
| Call graph | None | Full call tree with configurable depth |
| File I/O detection | Pattern match in disasm | Cross-reference analysis of import table |
| Harness style | Manual or basic auto-detect | Intelligent from parameter types |
| Coverage | Single function body | Nested calls traced via call graph |

---

## Command Reference

### Global Options

| Flag | Description |
|------|-------------|
| `--ghidra HOST:PORT` | Connect to Ghidra's REST API (e.g. `localhost:8192`) |
| `--arch {x64,x86}` | Target architecture (default: x64) |
| `--json-out` | Output analysis results as JSON |

### Commands

| Command | Description | Requires Ghidra? |
|---------|-------------|:---:|
| `analyze` | Deep-analyze a target function | Optional |
| `generate` | Generate harness C source code | Optional |
| `validate` | Pre-flight safety checks | No |
| `full` | analyze → generate → validate | Optional |
| `pipe` | Process piped JSON from target-finder | No |
| `auto` | Fully automated discovery + generation | **Yes** |
| `styles` | List available harness templates | No |

### Harness Styles

| Style | When to Use |
|-------|------------|
| `file_parser` | Function takes a file path (`LPCWSTR filename`) |
| `stream_parser` | Function takes a pre-opened handle (`HANDLE hFile`) |
| `buffer_parser` | Function takes `(BYTE* buf, size_t len)` |
| `dll_export` | Generic DLL export via `LoadLibrary` + offset |
| `com_interface` | COM object method fuzzing |
| `custom` | Minimal skeleton for manual coding |
| `auto` | Auto-detect from analysis/Ghidra params (default) |

---

## Linux-Specific Notes

### Running WinAFL Harnesses on Linux

WinAFL is Windows-only, but the **analysis and harness generation tools work on Linux**:

```bash
# Analysis on Linux (Ghidra runs natively on Linux)
python3 ghidra_bridge.py --test localhost:8192
python3 winafl-harness-builder.py auto target.dll --ghidra localhost:8192 --out harness/

# Cross-compile harnesses for Windows (using MinGW)
x86_64-w64-mingw32-gcc -o harness.exe harness/harness_target_41040.c -lole32
```

### Ghidra Headless Mode (Linux)

For CI/CD or batch processing, use Ghidra's headless analyzer:

```bash
# Import binary into a Ghidra project (headless)
/opt/ghidra/support/analyzeHeadless /tmp/ghidra_project MyProject \
    -import /path/to/target.dll -scriptPath /path/to/ghydramcp/scripts

# Start the GhydraMCP HTTP server in headless mode
# (See GhydraMCP documentation for headless setup)
```

### Python Path Setup (Linux)

```bash
# Ensure both scripts can find each other
export PYTHONPATH="/path/to/winafl:$PYTHONPATH"

# Or just run from the WinAFL directory
cd /path/to/winafl
python3 winafl-harness-builder.py auto target.dll --ghidra localhost:8192
```

---

## Troubleshooting

### Connection Issues

#### "Cannot connect to Ghidra at localhost:8192"

**Cause:** Ghidra is not running, plugin is not enabled, or wrong port.

**Fix:**
```bash
# 1. Verify Ghidra is running with the plugin
#    In Ghidra: File → Configure → Developer → Check GhydraMCP is enabled

# 2. Check the port
#    GhydraMCP default: 8192
#    GhidraMCP default: 8080
#    Try both:
python ghidra_bridge.py --test localhost:8192
python ghidra_bridge.py --test localhost:8080

# 3. Check if the HTTP server is listening (Windows)
netstat -ano | findstr :8192

# 3. Check if the HTTP server is listening (Linux)
ss -tlnp | grep 8192
# or
curl -s http://localhost:8192/api/instances

# 4. Check Ghidra console for errors
#    Window → Scripting → Console Log
```

#### "Could not connect — falling back to dumpbin"

**Cause:** `--ghidra` was specified but connection failed. The tool continues with dumpbin fallback.

**Fix:** This is non-fatal. The tool will still work, just without Ghidra's deep analysis. Fix the connection to get the enhanced results.

### Import/Module Issues

#### "ghidra_bridge not found" or "HAS_GHIDRA_BRIDGE is False"

**Cause:** `ghidra_bridge.py` is not in the same directory as `winafl-harness-builder.py`.

**Fix:**
```bash
# Ensure both files are in the same directory
ls ghidra_bridge.py winafl-harness-builder.py    # Linux
dir ghidra_bridge.py winafl-harness-builder.py    # Windows

# Or add to PYTHONPATH
export PYTHONPATH="/path/to/winafl:$PYTHONPATH"   # Linux
set PYTHONPATH=z:\WinAFL CUDA2;%PYTHONPATH%        # Windows
```

#### "I/O operation on closed file" (Windows only)

**Cause:** Previous terminal session had a broken stdout/stderr wrapper.

**Fix:** Close and reopen the terminal (cmd.exe or PowerShell), then retry.

### Analysis Issues

#### "No candidates found" in auto mode

**Cause:** The binary may not export parser-like functions or import file I/O APIs.

**Fix:**
```bash
# 1. Check what functions Ghidra sees
python ghidra_bridge.py --list-functions localhost:8192 --limit 100

# 2. Check imports
python ghidra_bridge.py --list-imports localhost:8192

# 3. Try manual analysis with a known offset
python winafl-harness-builder.py analyze target.dll --offset 0x1000 --ghidra localhost:8192
```

#### "Function body is very small — may be a thunk/stub"

**Cause:** The function at the specified offset is a thin wrapper that jumps to another function.

**Fix:**
```bash
# Use Ghidra to decompile and find the real implementation
python ghidra_bridge.py --decompile 0x41040 localhost:8192

# Look at the call graph to find the actual parsing function
python ghidra_bridge.py --callgraph 0x41040 localhost:8192 --depth 3
```

#### "FATAL: Function calls ExitProcess"

**Cause:** The function terminates the process, making it incompatible with WinAFL's loop mechanism.

**Fix:** Choose a different function that returns normally. Use the `auto` command to find safe candidates, or manually pick a function deeper in the call chain that does the parsing without exiting.

### Compilation Issues

#### "cl.exe not found" (Windows)

**Fix:**
```cmd
REM Open a Developer Command Prompt for VS, or:
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl.exe /nologo /W3 /O2 harness\harness_target_41040.c
```

#### Cross-compiling on Linux

```bash
# Install MinGW
sudo apt install gcc-mingw-w64-x86-64      # Debian/Ubuntu
sudo dnf install mingw64-gcc                 # Fedora

# Compile
x86_64-w64-mingw32-gcc -o harness.exe harness/harness_target_41040.c \
    -lkernel32 -lole32 -lgdi32
```

### Ghidra Plugin Issues

#### Ghidra rejects the .zip file ("Not a valid extension")

**Cause:** You're trying to install the outer "Complete" zip instead of the inner plugin zip.

**Fix:**
```
1. Unpack GhydraMCP-Complete-2.2.0.zip first
2. Inside you'll find GhydraMCP-2.2.0.zip (the actual plugin)
3. Install THAT file via File → Install Extensions → +
```

If it still doesn't work (version mismatch with your Ghidra):
```bash
# Manual install:
# Windows:
cd %USERPROFILE%\.ghidra\ghidra_11.3_PUBLIC\Extensions
mkdir GhydraMCP
# Extract GhydraMCP-2.2.0.zip contents here

# Linux:
cd ~/.ghidra/ghidra_11.3_PUBLIC/Extensions
mkdir GhydraMCP
unzip GhydraMCP-2.2.0.zip -d GhydraMCP/

# Or build from source (always matches your Ghidra):
git clone https://github.com/starsong-consulting/GhydraMCP.git
cd GhydraMCP
export GHIDRA_INSTALL_DIR=/path/to/ghidra
mvn clean package -P plugin-only
```

#### Plugin not showing in Ghidra Configure menu

**Fix:**
```
1. Ensure you installed the correct version for your Ghidra version
2. Check: File → Install Extensions → Verify the plugin is listed
3. Restart Ghidra completely (close ALL Ghidra windows)
4. File → Configure → Developer → Check the plugin checkbox
5. A tool restart is usually needed after enabling
```

#### Ghidra analysis hasn't completed

**Cause:** Auto-analysis may take several minutes for large binaries.

**Fix:**
```bash
# Check analysis status
python ghidra_bridge.py --test localhost:8192

# In Ghidra: Wait for the progress bar at bottom-right to finish
# Or trigger analysis manually: Analysis → Auto Analyze
```

---

## Architecture

### Files

| File | Purpose |
|------|---------|
| `ghidra_bridge.py` | Protocol-agnostic Ghidra HTTP client |
| `winafl-harness-builder.py` | Harness generation + analysis pipeline |
| `winafl-target-finder.py` | Target discovery + scoring |

### Data Flow

```
ghidra_bridge.py
    GhidraClient
        ├── connect()           → Auto-detect server type
        ├── decompile()         → C pseudocode
        ├── get_callgraph()     → Function call tree
        ├── get_xrefs()         → Cross-references
        ├── get_function()      → Signature + parameters
        ├── list_exports()      → Exported functions
        ├── list_imports()      → Imported APIs
        ├── find_fuzz_candidates()  → Automated scoring
        └── get_function_signature_c()  → Harness typedef

winafl-harness-builder.py
    DeepAnalyzer
        ├── _ghidra_enhance()   → Uses GhidraClient when available
        └── _disassemble()      → Uses dumpbin when Ghidra unavailable
    HarnessGenerator
        ├── _ghidra_typedef()   → Real params from Ghidra
        └── auto-detect style   → From Ghidra parameter types
```

### Supported REST API Endpoints

The bridge auto-detects the server type and adapts its HTTP calls:

| Endpoint | GhydraMCP | GhidraMCP | GhidrAssistMCP |
|----------|:---------:|:---------:|:--------------:|
| `/api/functions` | ✅ | ❌ | ❌ |
| `/api/functions/{id}/decompile` | ✅ | ❌ | ❌ |
| `/api/analysis/callgraph` | ✅ | ❌ | ❌ |
| `/api/analysis/dataflow` | ✅ | ❌ | ❌ |
| `/api/xrefs` | ✅ | ❌ | ❌ |
| `/methods` | ❌ | ✅ | ❌ |
| `/decompile/{name}` | ❌ | ✅ | ❌ |
| `/imports` | ❌ | ✅ | ✅ |
| `/exports` | ❌ | ✅ | ✅ |
