#!/usr/bin/env python3
"""
WinAFL Harness Builder - Automated Harness Generation & Deep Analysis Pipeline
Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)

Accepts piped JSON from winafl-target-finder.py or direct CLI arguments.
Performs deep binary analysis and generates ready-to-compile WinAFL harness code.

Pipeline usage:
    python winafl-target-finder.py harness target.dll | python winafl-harness-builder.py --pipe
    python winafl-target-finder.py harness target.dll --json | python winafl-harness-builder.py --pipe

Direct usage:
    python winafl-harness-builder.py analyze target.dll --offset 0x41040
    python winafl-harness-builder.py generate target.dll --offset 0x41040 --style file_parser
    python winafl-harness-builder.py validate target.dll --offset 0x41040 --drio C:\\DynamoRIO
    python winafl-harness-builder.py full target.dll --offset 0x41040 --drio C:\\DynamoRIO --out harness\\

Requirements:
    - Python 3.6+
    - dumpbin.exe (Visual Studio Build Tools)
    - cl.exe (for --compile flag)
    - DynamoRIO (for validate command)
"""

import os
import sys
import re
import io
import json
import struct
import subprocess
import argparse
import glob
import textwrap
from pathlib import Path
from collections import defaultdict

# Force UTF-8 on Windows (guard against double-wrapping when imported)
if sys.platform == "win32":
    if not isinstance(sys.stdout, io.TextIOWrapper) or sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass
    if not isinstance(sys.stderr, io.TextIOWrapper) or sys.stderr.encoding.lower() != 'utf-8':
        try:
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
        except (AttributeError, ValueError):
            pass

# Ghidra bridge (optional — enhanced analysis when Ghidra MCP is available)
try:
    from ghidra_bridge import GhidraClient
    HAS_GHIDRA_BRIDGE = True
except ImportError:
    HAS_GHIDRA_BRIDGE = False
    GhidraClient = None

# ============================================================================
# Tool Resolution
# ============================================================================

def find_tool(name, extra_globs=None):
    """Locate a build tool on the system."""
    try:
        r = subprocess.run(["where", name], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return r.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    for pattern in (extra_globs or []):
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return None

DUMPBIN = find_tool("dumpbin", [
    r"C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe"
])
CL = find_tool("cl", [
    r"C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"
])


# ============================================================================
# Deep Binary Analyzer
# ============================================================================

class DeepAnalyzer:
    """
    Performs deeper-than-export analysis on a target function:
    - Argument count inference from prologue
    - Call graph construction (what APIs does the function call?)
    - Safety validation for WinAFL compatibility
    - Calling convention detection
    """

    def __init__(self, binary_path, offset, arch="x64"):
        self.binary = binary_path
        self.offset = offset.lstrip("0x").lstrip("0X").upper()
        self.arch = arch
        self.module = os.path.basename(binary_path)

        # Analysis results
        self.disasm_lines = []
        self.called_apis = []
        self.arg_count = 0
        self.calling_convention = "fastcall" if arch == "x64" else "stdcall"
        self.opens_file = False
        self.closes_file = False
        self.calls_exit = False
        self.reads_data = False
        self.allocates_memory = False
        self.function_size = 0
        self.is_safe = True
        self.safety_warnings = []
        self.safety_errors = []

    def run_all(self, max_instructions=500, ghidra=None):
        """Run all analysis passes. If ghidra client is provided, use it."""
        if ghidra and ghidra.connected:
            self._ghidra_enhance(ghidra)
        else:
            self._disassemble(max_instructions)
        self._infer_args()
        self._trace_calls()
        self._validate_safety()
        return self.to_dict()

    def _ghidra_enhance(self, ghidra):
        """Use Ghidra for high-fidelity analysis instead of dumpbin."""
        addr = f"0x{self.offset}"

        # Get function info (signature, params)
        func = ghidra.get_function(addr)
        if func:
            if func.signature:
                self.ghidra_signature = func.signature
            if func.calling_convention:
                self.calling_convention = func.calling_convention
            if func.parameters and isinstance(func.parameters, list):
                self.arg_count = len(func.parameters)
                self.ghidra_params = func.parameters
            if func.size:
                self.function_size = func.size

        # Decompile — much richer than dumpbin disassembly
        code = ghidra.decompile(addr)
        if code:
            self.ghidra_decompiled = code
            # Parse decompiled C for behavioral flags
            for api in ["CreateFileA", "CreateFileW", "CreateFile2", "fopen", "_wfopen"]:
                if api in code:
                    self.opens_file = True
                    self.called_apis.append({"name": api, "category": "file_open"})
            for api in ["ReadFile", "fread", "_read", "fgets"]:
                if api in code:
                    self.reads_data = True
                    self.called_apis.append({"name": api, "category": "file_read"})
            for api in ["CloseHandle", "fclose", "_close"]:
                if api in code:
                    self.closes_file = True
                    self.called_apis.append({"name": api, "category": "file_close"})
            for api in ["malloc", "calloc", "HeapAlloc", "VirtualAlloc"]:
                if api in code:
                    self.allocates_memory = True
                    self.called_apis.append({"name": api, "category": "memory_alloc"})
            for api in ["ExitProcess", "TerminateProcess", "abort"]:
                if api in code:
                    self.calls_exit = True
                    self.called_apis.append({"name": api, "category": "process_exit"})

        # Call graph — trace deeper than single function
        graph = ghidra.get_callgraph(addr, max_depth=2)
        if graph:
            self.ghidra_callgraph = graph

        # Get variables for parameter type info
        variables = ghidra.get_function_variables(addr)
        if variables:
            self.ghidra_variables = variables
            params = [v for v in variables if v.is_parameter]
            if params:
                self.arg_count = len(params)
                self.ghidra_params = [
                    {"name": v.name, "type": v.data_type, "storage": v.storage}
                    for v in params
                ]

    def _disassemble(self, max_instructions):
        """Extract disassembly around the target offset."""
        if not DUMPBIN:
            self.safety_warnings.append("dumpbin not found — skipping disassembly analysis")
            return

        try:
            result = subprocess.run(
                [DUMPBIN, "/disasm", self.binary],
                capture_output=True, text=True, timeout=120,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
            if result.returncode != 0:
                return

            # Find our offset in the disassembly
            lines = result.stdout.splitlines()
            recording = False
            count = 0
            ret_count = 0

            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue

                # Match address lines
                m = re.match(r'^\s*([0-9A-Fa-f]{8,16}):', stripped)
                if m:
                    addr = m.group(1).upper()
                    # Convert to RVA
                    try:
                        addr_int = int(addr, 16)
                        if self.arch == "x64" and addr_int > 0x140000000:
                            rva = format(addr_int - 0x140000000, 'X')
                        elif self.arch != "x64" and addr_int > 0x10000000:
                            rva = format(addr_int - 0x10000000, 'X')
                        else:
                            rva = addr

                        if rva.lstrip('0') == self.offset.lstrip('0') or rva == self.offset:
                            recording = True
                    except ValueError:
                        pass

                if recording:
                    self.disasm_lines.append(stripped)
                    count += 1

                    # Stop at function epilogue (ret instruction)
                    if re.search(r'\bret\b', stripped, re.IGNORECASE):
                        ret_count += 1
                        if ret_count >= 2 or count > 50:
                            break

                    if count >= max_instructions:
                        break

            self.function_size = count

        except (subprocess.TimeoutExpired, MemoryError):
            self.safety_warnings.append("Disassembly timed out on large binary")

    def _infer_args(self):
        """Infer argument count from function prologue."""
        if not self.disasm_lines:
            self.arg_count = 2  # Default assumption
            return

        # x64 Windows fastcall: RCX, RDX, R8, R9, then stack
        # Look for register saves and stack parameter references
        arg_regs_used = set()
        x64_arg_regs = {"rcx": 1, "rdx": 2, "r8": 3, "r9": 4, "r8d": 3, "r9d": 4, "ecx": 1, "edx": 2}

        # Only scan prologue (first ~20 instructions)
        prologue = self.disasm_lines[:20]
        for line in prologue:
            lower = line.lower()
            for reg, idx in x64_arg_regs.items():
                if reg in lower:
                    arg_regs_used.add(idx)

            # Stack parameter references: [rsp+28h], [rsp+30h], etc.
            stack_match = re.search(r'\[rsp\+([0-9A-Fa-f]+)h?\]', lower)
            if stack_match:
                stack_off = int(stack_match.group(1), 16)
                if stack_off >= 0x28:  # 5th arg starts at rsp+28h (after shadow space)
                    arg_num = 5 + (stack_off - 0x28) // 8
                    arg_regs_used.add(arg_num)

        if arg_regs_used:
            self.arg_count = max(arg_regs_used)
        else:
            self.arg_count = 2  # Safe default

    def _trace_calls(self):
        """Extract API calls from the function body."""
        api_categories = {
            "file_open": ["CreateFileA", "CreateFileW", "CreateFile2", "fopen", "_wfopen", "_open"],
            "file_read": ["ReadFile", "ReadFileEx", "fread", "_read", "fgets", "fgetc"],
            "file_close": ["CloseHandle", "fclose", "_close"],
            "file_seek": ["SetFilePointer", "SetFilePointerEx", "fseek", "_lseek"],
            "file_map": ["CreateFileMappingW", "CreateFileMappingA", "MapViewOfFile", "UnmapViewOfFile"],
            "memory_alloc": ["malloc", "calloc", "realloc", "HeapAlloc", "VirtualAlloc", "LocalAlloc", "GlobalAlloc"],
            "memory_free": ["free", "HeapFree", "VirtualFree", "LocalFree", "GlobalFree"],
            "memory_copy": ["memcpy", "memmove", "memset", "RtlCopyMemory", "RtlMoveMemory"],
            "string_ops": ["strcpy", "strncpy", "wcsncpy", "lstrcpyW", "sprintf", "swprintf"],
            "process_exit": ["ExitProcess", "TerminateProcess", "abort", "exit", "_exit"],
            "exception": ["RaiseException", "FatalAppExitA", "FatalAppExitW"],
        }

        for line in self.disasm_lines:
            if "call" not in line.lower():
                continue
            for category, apis in api_categories.items():
                for api in apis:
                    if api in line:
                        self.called_apis.append({"name": api, "category": category})
                        if category == "file_open":
                            self.opens_file = True
                        elif category == "file_close":
                            self.closes_file = True
                        elif category == "file_read":
                            self.reads_data = True
                        elif category == "memory_alloc":
                            self.allocates_memory = True
                        elif category in ("process_exit", "exception"):
                            self.calls_exit = True

    def _validate_safety(self):
        """Validate whether this function is safe to fuzz with WinAFL."""
        # Critical errors (will not work)
        if self.calls_exit:
            self.safety_errors.append(
                "FATAL: Function calls ExitProcess/abort — WinAFL cannot loop it. "
                "Choose a different target function.")
            self.is_safe = False

        if not self.opens_file and not self.reads_data:
            self.safety_warnings.append(
                "WARNING: No file open/read calls detected in visible code. "
                "The function may delegate to a sub-call or accept pre-opened handles.")

        if self.opens_file and not self.closes_file:
            self.safety_warnings.append(
                "WARNING: Opens files but no close detected — WinAFL needs the file "
                "handle closed between iterations to overwrite the input file.")

        # Memory safety notes
        if self.allocates_memory:
            self.safety_warnings.append(
                "NOTE: Function allocates memory. Ensure it frees properly to "
                "avoid per-iteration leaks during long fuzzing runs.")

        # Size check
        if self.function_size < 5:
            self.safety_warnings.append(
                "WARNING: Function body is very small — may be a thunk/stub. "
                "The actual parsing may happen in a called function.")

    def to_dict(self):
        d = {
            "binary": self.binary,
            "module": self.module,
            "offset": self.offset,
            "arch": self.arch,
            "arg_count": self.arg_count,
            "calling_convention": self.calling_convention,
            "function_size": self.function_size,
            "opens_file": self.opens_file,
            "closes_file": self.closes_file,
            "reads_data": self.reads_data,
            "calls_exit": self.calls_exit,
            "allocates_memory": self.allocates_memory,
            "called_apis": self.called_apis,
            "is_safe": self.is_safe,
            "safety_warnings": self.safety_warnings,
            "safety_errors": self.safety_errors,
        }
        # Add Ghidra-specific fields if present
        if hasattr(self, 'ghidra_signature'):
            d["ghidra_signature"] = self.ghidra_signature
        if hasattr(self, 'ghidra_params'):
            d["ghidra_params"] = self.ghidra_params
        if hasattr(self, 'ghidra_decompiled'):
            d["ghidra_decompiled"] = self.ghidra_decompiled
        return d

    def print_report(self):
        """Print a human-readable analysis report."""
        print(f"\n{'='*70}")
        print(f"  Deep Analysis Report")
        print(f"  {self.module} + 0x{self.offset}")
        print(f"{'='*70}\n")

        print(f"  Architecture:       {self.arch}")
        print(f"  Calling convention: {self.calling_convention}")
        print(f"  Inferred args:      {self.arg_count}")
        print(f"  Function size:      ~{self.function_size} instructions")
        print()

        # API call summary
        if self.called_apis:
            print(f"  API Calls Detected:")
            by_cat = defaultdict(list)
            for api in self.called_apis:
                by_cat[api["category"]].append(api["name"])
            for cat, names in sorted(by_cat.items()):
                print(f"    [{cat}]  {', '.join(set(names))}")
            print()

        # Behavioral flags
        print(f"  Behavioral Flags:")
        flags = [
            ("Opens file",      self.opens_file),
            ("Reads data",      self.reads_data),
            ("Closes handle",   self.closes_file),
            ("Allocates memory", self.allocates_memory),
            ("Calls exit",      self.calls_exit),
        ]
        for label, val in flags:
            icon = "[Y]" if val else "[ ]"
            print(f"    {icon} {label}")
        print()

        # Safety assessment
        safe_label = "SAFE" if self.is_safe else "UNSAFE"
        print(f"  Safety: {safe_label}")
        for err in self.safety_errors:
            print(f"    [X] {err}")
        for warn in self.safety_warnings:
            print(f"    [!] {warn}")
        print()


# ============================================================================
# Harness Code Generator
# ============================================================================

class HarnessGenerator:
    """
    Generates C source code for WinAFL harnesses.
    Multiple styles for different target patterns.
    """

    STYLES = {
        "file_parser":    "Target function opens, reads, and closes a file path argument",
        "stream_parser":  "Target function accepts a pre-opened stream/handle",
        "buffer_parser":  "Target function accepts a buffer pointer + length",
        "dll_export":     "Fuzzing a DLL exported function via LoadLibrary + GetProcAddress",
        "com_interface":  "Fuzzing a COM interface method",
        "custom":         "Minimal skeleton — fill in your own logic",
    }

    def __init__(self, analysis, style="auto", **kwargs):
        self.a = analysis  # DeepAnalyzer results dict
        self.style = style
        self.opts = kwargs

        # Auto-detect style from analysis / Ghidra params
        if style == "auto":
            ghidra_params = analysis.get("ghidra_params", [])
            if ghidra_params:
                # Inspect parameter types from Ghidra
                param_types = [p.get("type", "").lower() if isinstance(p, dict) else "" for p in ghidra_params]
                type_str = " ".join(param_types)
                if any(t in type_str for t in ["handle", "hfile", "stream"]):
                    self.style = "stream_parser"
                elif any(t in type_str for t in ["byte *", "char *", "uchar *", "void *", "pbyte"]):
                    # Check if there's also a length param
                    if any(t in type_str for t in ["size_t", "uint", "int", "dword", "ulong"]):
                        self.style = "buffer_parser"
                    else:
                        self.style = "file_parser"
                elif any(t in type_str for t in ["wchar", "lpcwstr", "lpwstr", "lpcstr"]):
                    self.style = "file_parser"
                else:
                    self.style = "dll_export" if Path(analysis.get("binary", "")).suffix.lower() == ".dll" else "file_parser"
            elif analysis.get("opens_file") and analysis.get("closes_file"):
                self.style = "file_parser"
            elif analysis.get("reads_data") and not analysis.get("opens_file"):
                self.style = "buffer_parser"
            elif Path(analysis.get("binary", "")).suffix.lower() == ".dll":
                self.style = "dll_export"
            else:
                self.style = "file_parser"

    def generate(self):
        """Generate the harness C source code."""
        method = getattr(self, f"_gen_{self.style}", self._gen_custom)
        return method()

    def _ghidra_typedef(self):
        """Generate typedef from Ghidra signature if available."""
        sig = self.a.get("ghidra_signature", "")
        params = self.a.get("ghidra_params", [])

        if params and isinstance(params, list) and isinstance(params[0], dict):
            # Build typedef from Ghidra parameter info
            param_strs = []
            for p in params:
                ptype = p.get("type", "void *")
                pname = p.get("name", "param")
                param_strs.append(f"{ptype} {pname}")
            params_c = ", ".join(param_strs) if param_strs else "void"
            return f"/* Ghidra-derived signature */\ntypedef int (WINAPI *TargetFunc)({params_c});"

        if sig:
            # Try to convert Ghidra signature to typedef
            return f"/* Ghidra signature: {sig} */\ntypedef int (WINAPI *TargetFunc)(const wchar_t* input_path);"

        # Fallback
        return "typedef int (WINAPI *TargetFunc)(const wchar_t* input_path);"

    def _header(self):
        """Common header for all harnesses."""
        return textwrap.dedent(f"""\
        /*
         * WinAFL Harness — Auto-generated by winafl-harness-builder
         *
         * Target:  {self.a['module']}
         * Offset:  0x{self.a['offset']}
         * Style:   {self.style}
         * Args:    {self.a['arg_count']}
         *
         * Build:
         *   cl.exe /nologo /W3 /O2 harness.c /link /OUT:harness.exe
         *
         * Verify:
         *   drrun.exe -c winafl.dll -debug
         *     -target_module harness.exe -target_offset 0x<HARNESS_FUNC_RVA>
         *     -fuzz_iterations 10 -nargs 2
         *     -- harness.exe input.bin
         *
         * Fuzz:
         *   afl-fuzz.exe -G -i in -o out -t 2000
         *     -D <DynamoRIO> --
         *     -target_module harness.exe -target_offset 0x<HARNESS_FUNC_RVA>
         *     -coverage_module {self.a['module']}
         *     -fuzz_iterations 5000 -nargs 2
         *     -- harness.exe @@
         */
        """)

    def _gen_file_parser(self):
        module = self.a["module"]
        offset = self.a["offset"]
        nargs = self.a["arg_count"]
        is_dll = module.lower().endswith(".dll")

        if is_dll:
            return self._header() + textwrap.dedent(f"""\
            #include <windows.h>
            #include <stdio.h>

            /* ---- Configuration ---- */
            #define TARGET_DLL      "{module}"
            #define TARGET_OFFSET   0x{offset}

            /* Typedef for the target function.
             * Adjust return type and parameters to match the real signature.
             * Use IDA/Ghidra to confirm the prototype. */
            {self._ghidra_typedef()}

            /* ---- WinAFL fuzz target ---- */
            /* This is the function WinAFL will loop on.
             * -target_module harness.exe -target_offset <RVA of fuzz_target>
             * -nargs 2 (argc, argv — WinAFL passes during iteration)  */
            int fuzz_target(int argc, char** argv) {{
                if (argc < 2) {{
                    fprintf(stderr, "Usage: harness.exe <input_file>\\n");
                    return 1;
                }}

                /* Convert input path to wide string */
                wchar_t wpath[MAX_PATH];
                MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, MAX_PATH);

                /* Load the target DLL and resolve the function */
                static HMODULE hMod = NULL;
                static TargetFunc pTarget = NULL;

                if (!hMod) {{
                    hMod = LoadLibraryA(TARGET_DLL);
                    if (!hMod) {{
                        fprintf(stderr, "[-] Failed to load %s (err=%lu)\\n",
                                TARGET_DLL, GetLastError());
                        return 1;
                    }}

                    /* Calculate function address from base + offset */
                    pTarget = (TargetFunc)((BYTE*)hMod + TARGET_OFFSET);
                    fprintf(stderr, "[+] Loaded %s, target at %p\\n",
                            TARGET_DLL, pTarget);
                }}

                /* Call the target — WinAFL will mutate argv[1] between iterations */
                __try {{
                    pTarget(wpath);
                }} __except(EXCEPTION_EXECUTE_HANDLER) {{
                    /* Swallow crashes — WinAFL sees them via debug events */
                }}

                return 0;
            }}

            int main(int argc, char** argv) {{
                return fuzz_target(argc, argv);
            }}
            """)
        else:
            # EXE target — harness wraps the target offset directly
            return self._header() + textwrap.dedent(f"""\
            #include <windows.h>
            #include <stdio.h>

            /* ---- Configuration ---- */
            #define TARGET_EXE      "{module}"
            #define TARGET_OFFSET   0x{offset}

            /* Typedef — adjust to match the real function signature */
            typedef int (*TargetFunc)(const char* filename);

            int fuzz_target(int argc, char** argv) {{
                if (argc < 2) {{
                    fprintf(stderr, "Usage: harness.exe <input_file>\\n");
                    return 1;
                }}

                /* The target is in the same process — resolve once */
                static TargetFunc pTarget = NULL;
                if (!pTarget) {{
                    HMODULE hMod = GetModuleHandleA(NULL);
                    pTarget = (TargetFunc)((BYTE*)hMod + TARGET_OFFSET);
                }}

                __try {{
                    pTarget(argv[1]);
                }} __except(EXCEPTION_EXECUTE_HANDLER) {{
                    /* Swallow */
                }}

                return 0;
            }}

            int main(int argc, char** argv) {{
                return fuzz_target(argc, argv);
            }}
            """)

    def _gen_stream_parser(self):
        module = self.a["module"]
        offset = self.a["offset"]
        return self._header() + textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>

        #define TARGET_DLL      "{module}"
        #define TARGET_OFFSET   0x{offset}

        /* Target accepts a pre-opened HANDLE */
        typedef int (WINAPI *TargetFunc)(HANDLE hFile);

        int fuzz_target(int argc, char** argv) {{
            if (argc < 2) return 1;

            static HMODULE hMod = NULL;
            static TargetFunc pTarget = NULL;

            if (!hMod) {{
                hMod = LoadLibraryA(TARGET_DLL);
                if (!hMod) return 1;
                pTarget = (TargetFunc)((BYTE*)hMod + TARGET_OFFSET);
            }}

            /* Open the file, pass handle, close — WinAFL needs the close */
            HANDLE hFile = CreateFileA(
                argv[1], GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (hFile == INVALID_HANDLE_VALUE) return 1;

            __try {{
                pTarget(hFile);
            }} __except(EXCEPTION_EXECUTE_HANDLER) {{
                /* swallow */
            }}

            CloseHandle(hFile);
            return 0;
        }}

        int main(int argc, char** argv) {{
            return fuzz_target(argc, argv);
        }}
        """)

    def _gen_buffer_parser(self):
        module = self.a["module"]
        offset = self.a["offset"]
        return self._header() + textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>
        #include <stdlib.h>

        #define TARGET_DLL      "{module}"
        #define TARGET_OFFSET   0x{offset}

        /* Target accepts a buffer + size */
        typedef int (WINAPI *TargetFunc)(const unsigned char* buf, size_t len);

        int fuzz_target(int argc, char** argv) {{
            if (argc < 2) return 1;

            static HMODULE hMod = NULL;
            static TargetFunc pTarget = NULL;

            if (!hMod) {{
                hMod = LoadLibraryA(TARGET_DLL);
                if (!hMod) return 1;
                pTarget = (TargetFunc)((BYTE*)hMod + TARGET_OFFSET);
            }}

            /* Read entire file into memory */
            FILE* f = fopen(argv[1], "rb");
            if (!f) return 1;

            fseek(f, 0, SEEK_END);
            long file_size = ftell(f);
            fseek(f, 0, SEEK_SET);

            if (file_size <= 0 || file_size > 10 * 1024 * 1024) {{
                fclose(f);
                return 1;  /* Skip files > 10MB */
            }}

            unsigned char* buf = (unsigned char*)malloc(file_size);
            if (!buf) {{ fclose(f); return 1; }}

            fread(buf, 1, file_size, f);
            fclose(f);

            __try {{
                pTarget(buf, (size_t)file_size);
            }} __except(EXCEPTION_EXECUTE_HANDLER) {{
                /* swallow */
            }}

            free(buf);
            return 0;
        }}

        int main(int argc, char** argv) {{
            return fuzz_target(argc, argv);
        }}
        """)

    def _gen_dll_export(self):
        module = self.a["module"]
        offset = self.a["offset"]
        # Try to find export name for this offset
        export_name = self.opts.get("export_name", None)
        if export_name:
            resolve_code = f'pTarget = (TargetFunc)GetProcAddress(hMod, "{export_name}");'
        else:
            resolve_code = f"pTarget = (TargetFunc)((BYTE*)hMod + 0x{offset});"

        return self._header() + textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>

        #define TARGET_DLL "{module}"

        /* Adjust the typedef to match the exported function's real signature.
         * Use: dumpbin /exports {module}
         * Then look up the function in IDA/Ghidra to confirm args. */
        typedef int (WINAPI *TargetFunc)(const wchar_t* input_path);

        int fuzz_target(int argc, char** argv) {{
            if (argc < 2) return 1;

            static HMODULE hMod = NULL;
            static TargetFunc pTarget = NULL;

            if (!hMod) {{
                hMod = LoadLibraryA(TARGET_DLL);
                if (!hMod) {{
                    fprintf(stderr, "[-] LoadLibrary failed: %lu\\n", GetLastError());
                    return 1;
                }}
                {resolve_code}
                if (!pTarget) {{
                    fprintf(stderr, "[-] Could not resolve target function\\n");
                    return 1;
                }}
                fprintf(stderr, "[+] Target resolved at %p\\n", pTarget);
            }}

            wchar_t wpath[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, MAX_PATH);

            __try {{
                pTarget(wpath);
            }} __except(EXCEPTION_EXECUTE_HANDLER) {{
                /* swallow */
            }}

            return 0;
        }}

        int main(int argc, char** argv) {{
            return fuzz_target(argc, argv);
        }}
        """)

    def _gen_com_interface(self):
        module = self.a["module"]
        offset = self.a["offset"]
        return self._header() + textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>
        #include <objbase.h>

        /* ---- COM Configuration ----
         * Set the CLSID and IID for your target COM object.
         * Find these in the registry or with OleView. */
        // DEFINE_GUID(CLSID_Target, 0x..., 0x..., 0x..., ...);
        // DEFINE_GUID(IID_ITarget, 0x..., 0x..., 0x..., ...);

        int fuzz_target(int argc, char** argv) {{
            if (argc < 2) return 1;

            static int com_initialized = 0;
            if (!com_initialized) {{
                CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
                com_initialized = 1;
            }}

            wchar_t wpath[MAX_PATH];
            MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, MAX_PATH);

            /* TODO: Create COM object and call the target method
             *
             * IUnknown* pUnk = NULL;
             * HRESULT hr = CoCreateInstance(&CLSID_Target, NULL,
             *     CLSCTX_INPROC_SERVER, &IID_ITarget, (void**)&pUnk);
             *
             * if (SUCCEEDED(hr)) {{
             *     // Call method with wpath
             *     pUnk->lpVtbl->Release(pUnk);
             * }}
             */

            fprintf(stderr, "[!] COM harness template — fill in CLSID/IID and method call\\n");
            return 0;
        }}

        int main(int argc, char** argv) {{
            return fuzz_target(argc, argv);
        }}
        """)

    def _gen_custom(self):
        module = self.a["module"]
        offset = self.a["offset"]
        return self._header() + textwrap.dedent(f"""\
        #include <windows.h>
        #include <stdio.h>

        #define TARGET_MODULE "{module}"
        #define TARGET_OFFSET 0x{offset}

        /*
         * Custom harness skeleton.
         * Fill in your own target function call logic below.
         *
         * Analysis detected {self.a['arg_count']} arguments.
         * Called APIs: {', '.join(a['name'] for a in self.a.get('called_apis', [])) or 'none detected'}
         */

        int fuzz_target(int argc, char** argv) {{
            if (argc < 2) {{
                fprintf(stderr, "Usage: harness.exe <input_file>\\n");
                return 1;
            }}

            /* TODO: Your target call here */
            fprintf(stderr, "Input: %s\\n", argv[1]);

            return 0;
        }}

        int main(int argc, char** argv) {{
            return fuzz_target(argc, argv);
        }}
        """)


# ============================================================================
# Harness Validator
# ============================================================================

class HarnessValidator:
    """
    Pre-flight safety checks before running a harness.
    Validates without executing anything dangerous.
    """

    def __init__(self, binary, offset, drio_dir=None, harness_exe=None):
        self.binary = binary
        self.offset = offset
        self.drio_dir = drio_dir
        self.harness_exe = harness_exe
        self.checks = []

    def validate_all(self):
        """Run all validation checks."""
        self._check_binary_exists()
        self._check_binary_bitness()
        self._check_offset_in_range()
        self._check_drio()
        self._check_harness()
        return self.checks

    def _check_binary_exists(self):
        exists = os.path.exists(self.binary)
        self.checks.append({
            "name": "Target binary exists",
            "ok": exists,
            "detail": self.binary if exists else f"NOT FOUND: {self.binary}"
        })

    def _check_binary_bitness(self):
        try:
            with open(self.binary, "rb") as f:
                dos_sig = f.read(2)
                if dos_sig != b"MZ":
                    self.checks.append({"name": "Valid PE", "ok": False, "detail": "Not a PE file"})
                    return
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset + 4)
                machine = struct.unpack("<H", f.read(2))[0]
                arch = "x64" if machine == 0x8664 else "x86"
                self.checks.append({
                    "name": "Architecture",
                    "ok": True,
                    "detail": arch
                })
        except Exception as e:
            self.checks.append({"name": "PE analysis", "ok": False, "detail": str(e)})

    def _check_offset_in_range(self):
        try:
            offset_int = int(self.offset.lstrip("0x").lstrip("0X"), 16)
            file_size = os.path.getsize(self.binary)
            in_range = offset_int < file_size
            self.checks.append({
                "name": "Offset in range",
                "ok": in_range,
                "detail": f"0x{offset_int:X} {'<' if in_range else '>='} file size {file_size:,d}"
            })
        except Exception:
            self.checks.append({"name": "Offset check", "ok": False, "detail": "Invalid offset"})

    def _check_drio(self):
        if not self.drio_dir:
            self.checks.append({"name": "DynamoRIO", "ok": False, "detail": "Not specified (--drio)"})
            return
        drrun = os.path.join(self.drio_dir, "bin64", "drrun.exe")
        exists = os.path.exists(drrun)
        self.checks.append({
            "name": "DynamoRIO drrun.exe",
            "ok": exists,
            "detail": drrun if exists else f"NOT FOUND: {drrun}"
        })

    def _check_harness(self):
        if self.harness_exe:
            exists = os.path.exists(self.harness_exe)
            self.checks.append({
                "name": "Harness executable",
                "ok": exists,
                "detail": self.harness_exe if exists else f"NOT FOUND: {self.harness_exe}"
            })

    def print_report(self):
        print(f"\n{'='*70}")
        print(f"  Pre-Flight Validation")
        print(f"{'='*70}\n")

        all_ok = True
        for c in self.checks:
            icon = "[OK]" if c["ok"] else "[!!]"
            print(f"  {icon} {c['name']}: {c['detail']}")
            if not c["ok"]:
                all_ok = False

        print()
        if all_ok:
            print(f"  All checks passed — safe to proceed.")
        else:
            print(f"  Some checks failed — resolve issues before fuzzing.")
        print()
        return all_ok


# ============================================================================
# Pipeline Integration
# ============================================================================

def read_pipe_input():
    """Read JSON from stdin (piped from winafl-target-finder.py harness --json)."""
    if sys.stdin.isatty():
        return None

    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
        return data
    except (json.JSONDecodeError, ValueError):
        # Try line-by-line parsing (the harness command doesn't output JSON yet,
        # so also try parsing the structured text output)
        return None


# ============================================================================
# Ghidra Connection Helper
# ============================================================================

def _connect_ghidra(args):
    """Try to connect to Ghidra if --ghidra flag is set."""
    ghidra_addr = getattr(args, 'ghidra', None)
    if not ghidra_addr or not HAS_GHIDRA_BRIDGE:
        return None

    if ":" in ghidra_addr:
        host, port_str = ghidra_addr.rsplit(":", 1)
        port = int(port_str)
    else:
        host, port = ghidra_addr, 8192

    client = GhidraClient(host, port)
    if client.connect():
        print(f"  [GHIDRA] Connected to {client.server_type} at {host}:{port}")
        return client
    else:
        print(f"  [GHIDRA] Could not connect to {host}:{port} — falling back to dumpbin")
        return None


# ============================================================================
# CLI Commands
# ============================================================================

def cmd_analyze(args):
    """Deep-analyze a target function."""
    offset = args.offset.lstrip("0x").lstrip("0X")
    ghidra = _connect_ghidra(args)
    analyzer = DeepAnalyzer(args.binary, offset, arch=args.arch)
    results = analyzer.run_all(ghidra=ghidra)
    analyzer.print_report()

    # Show decompiled code if available from Ghidra
    if hasattr(analyzer, 'ghidra_decompiled') and analyzer.ghidra_decompiled:
        print(f"  Decompiled Code (via Ghidra):")
        print(f"  {'-'*60}")
        for line in analyzer.ghidra_decompiled.splitlines()[:40]:
            print(f"    {line}")
        print(f"  {'-'*60}\n")

    if args.json_out:
        print(json.dumps(results, indent=2))

    return results


def cmd_generate(args):
    """Generate a harness source file."""
    offset = args.offset.lstrip("0x").lstrip("0X")

    # Run analysis first (with Ghidra if available)
    ghidra = _connect_ghidra(args)
    analyzer = DeepAnalyzer(args.binary, offset, arch=args.arch)
    results = analyzer.run_all(ghidra=ghidra)

    # Generate harness
    gen = HarnessGenerator(
        results,
        style=args.style,
        export_name=getattr(args, 'export_name', None),
    )
    source = gen.generate()

    # Output
    out_dir = args.out or "."
    os.makedirs(out_dir, exist_ok=True)

    module_base = Path(args.binary).stem
    out_file = os.path.join(out_dir, f"harness_{module_base}_{offset}.c")

    with open(out_file, "w") as f:
        f.write(source)

    print(f"\n{'='*70}")
    print(f"  Harness Generated")
    print(f"{'='*70}\n")
    print(f"  Style:   {gen.style}")
    print(f"  Output:  {out_file}")
    print(f"  Args:    {results['arg_count']}")

    if results['safety_errors']:
        print(f"\n  SAFETY ERRORS:")
        for e in results['safety_errors']:
            print(f"    [X] {e}")

    if results['safety_warnings']:
        print(f"\n  WARNINGS:")
        for w in results['safety_warnings']:
            print(f"    [!] {w}")

    # Compile if requested
    if args.compile:
        print(f"\n  Compiling...")
        out_exe = out_file.replace(".c", ".exe")
        cl = CL or "cl"
        cmd = f'"{cl}" /nologo /W3 /O2 "{out_file}" /link /OUT:"{out_exe}"'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                print(f"  [OK] Compiled: {out_exe}")
            else:
                print(f"  [!!] Compilation failed:")
                print(f"       {result.stderr[:300]}")
        except subprocess.TimeoutExpired:
            print(f"  [!!] Compilation timed out")

    print(f"\n  Next steps:")
    print(f"    1. Review and adjust the typedef in {out_file}")
    print(f"    2. Compile: cl.exe /nologo /W3 /O2 {out_file}")
    print(f"    3. Verify: python winafl-target-finder.py verify harness.exe <offset> <drio>")
    print()

    return out_file


def cmd_validate(args):
    """Pre-flight validation."""
    offset = args.offset.lstrip("0x").lstrip("0X")
    validator = HarnessValidator(
        args.binary, offset,
        drio_dir=args.drio,
        harness_exe=getattr(args, 'harness_exe', None),
    )
    checks = validator.validate_all()
    validator.print_report()

    # Also run deep analysis
    analyzer = DeepAnalyzer(args.binary, offset, arch=args.arch)
    analyzer.run_all()
    analyzer.print_report()


def cmd_full(args):
    """Full pipeline: analyze → generate → validate."""
    offset = args.offset.lstrip("0x").lstrip("0X")

    print(f"\n{'='*70}")
    print(f"  Full Pipeline: {args.binary} + 0x{offset}")
    print(f"{'='*70}")

    # Step 1: Deep analysis
    ghidra = _connect_ghidra(args)
    ghidra_label = " + Ghidra" if ghidra else ""
    print(f"\n  [1/3] Deep Analysis{ghidra_label}...")
    analyzer = DeepAnalyzer(args.binary, offset, arch=args.arch)
    results = analyzer.run_all(ghidra=ghidra)
    analyzer.print_report()

    if not results["is_safe"]:
        print(f"  [!!] Target is NOT SAFE for WinAFL. Aborting.")
        print(f"       Fix the safety errors above or choose a different offset.")
        return

    # Step 2: Generate harness
    print(f"\n  [2/3] Generating Harness...")
    gen = HarnessGenerator(results, style=args.style)
    source = gen.generate()

    out_dir = args.out or "harness"
    os.makedirs(out_dir, exist_ok=True)
    module_base = Path(args.binary).stem
    out_file = os.path.join(out_dir, f"harness_{module_base}_{offset}.c")

    with open(out_file, "w") as f:
        f.write(source)
    print(f"  [OK] Harness written to: {out_file}")
    print(f"  [OK] Style: {gen.style}")

    # Step 3: Validate
    print(f"\n  [3/3] Pre-Flight Validation...")
    validator = HarnessValidator(
        args.binary, offset,
        drio_dir=args.drio,
    )
    validator.validate_all()
    validator.print_report()

    # Summary
    print(f"  {'='*60}")
    print(f"  PIPELINE COMPLETE")
    print(f"  {'='*60}\n")
    print(f"  Harness:  {out_file}")
    print(f"  Style:    {gen.style}")
    print(f"  Args:     {results['arg_count']}")
    print()
    print(f"  Next steps:")
    print(f"    1. Review {out_file} — adjust the typedef to match the real signature")
    print(f"    2. Compile: cl.exe /nologo /W3 /O2 \"{out_file}\"")
    if args.drio:
        harness_exe = out_file.replace(".c", ".exe")
        print(f"    3. Verify:  drrun.exe -c winafl.dll -debug "
              f"-target_module {os.path.basename(harness_exe)} "
              f"-target_offset <RVA> -fuzz_iterations 10 -nargs 2 "
              f"-- {harness_exe} input.bin")
    print()


def cmd_auto(args):
    """Fully automated: discover targets via Ghidra + generate harnesses."""
    ghidra = _connect_ghidra(args)
    if not ghidra:
        print(f"\n  [!!] The 'auto' command requires a Ghidra MCP connection.")
        print(f"       Start Ghidra with the GhydraMCP plugin, load your binary, then run:")
        print(f"       python winafl-harness-builder.py auto {args.binary} --ghidra localhost:8192")
        if not HAS_GHIDRA_BRIDGE:
            print(f"\n       Also ensure ghidra_bridge.py is in the same directory.")
        return

    print(f"\n{'='*70}")
    print(f"  Automated Harness Discovery + Generation")
    print(f"  Target: {args.binary}")
    print(f"  Ghidra: {args.ghidra}")
    print(f"{'='*70}")

    # Step 1: Auto-discover fuzz candidates via Ghidra
    print(f"\n  [1/4] Discovering fuzzing candidates via Ghidra...")
    candidates = ghidra.find_fuzz_candidates()

    if not candidates:
        print(f"  [!!] No candidates found. The binary may not have relevant exports")
        print(f"       or file I/O imports. Try manual analysis with:")
        print(f"       python winafl-harness-builder.py analyze {args.binary} --offset <addr> --ghidra {args.ghidra}")
        return

    limit = args.limit or 5
    print(f"  [OK] Found {len(candidates)} candidates, processing top {limit}\n")

    for i, cand in enumerate(candidates[:limit]):
        name = cand.get("name", "unknown")
        addr = cand.get("address", "0")
        score = cand.get("score", 0)
        print(f"  #{i+1:2d}  [Score: {score:3d}]  {addr}  {name}")
        for r in cand.get("reasons", []):
            print(f"       + {r}")

    # Step 2: Deep-analyze the top candidates
    print(f"\n  [2/4] Deep-analyzing top candidates via Ghidra decompilation...")
    viable = []
    for cand in candidates[:limit]:
        addr = cand.get("address", "")
        name = cand.get("name", "unknown")
        if not addr:
            continue

        offset = addr.lstrip("0x").lstrip("0X").upper()
        analyzer = DeepAnalyzer(args.binary, offset, arch=args.arch)
        results = analyzer.run_all(ghidra=ghidra)

        if results["is_safe"]:
            viable.append({"candidate": cand, "analysis": results, "offset": offset})
            sig_info = f" | sig: {results.get('ghidra_signature', 'unknown')}" if results.get("ghidra_signature") else ""
            print(f"    [OK] {name} — {results['arg_count']} args, safe{sig_info}")
        else:
            print(f"    [XX] {name} — UNSAFE: {results['safety_errors'][0][:60]}")

    if not viable:
        print(f"\n  [!!] No viable candidates passed safety analysis.")
        return

    # Step 3: Generate harnesses
    print(f"\n  [3/4] Generating harnesses for {len(viable)} viable candidates...")
    out_dir = args.out or "harness"
    os.makedirs(out_dir, exist_ok=True)

    generated = []
    for v in viable:
        results = v["analysis"]
        offset = v["offset"]
        name = v["candidate"].get("name", "func")

        gen = HarnessGenerator(results, style=args.style, export_name=name)
        source = gen.generate()

        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        out_file = os.path.join(out_dir, f"harness_{safe_name}_{offset}.c")
        with open(out_file, "w") as f:
            f.write(source)

        generated.append({"file": out_file, "name": name, "offset": offset, "style": gen.style})
        print(f"    [OK] {out_file} (style: {gen.style})")

    # Step 4: Summary
    print(f"\n  [4/4] Validation Summary...")
    validator = HarnessValidator(args.binary, viable[0]["offset"], drio_dir=getattr(args, 'drio', None))
    validator.validate_all()
    validator.print_report()

    print(f"  {'='*60}")
    print(f"  AUTO-GENERATION COMPLETE")
    print(f"  {'='*60}\n")
    print(f"  Generated {len(generated)} harness(es) in {out_dir}/\n")

    for g in generated:
        print(f"    {g['file']}")
        print(f"      Target: {g['name']} @ 0x{g['offset']}, Style: {g['style']}")

    print(f"\n  Next steps:")
    print(f"    1. Review the generated .c files — adjust typedefs if needed")
    print(f"    2. Compile: cl.exe /nologo /W3 /O2 harness\\harness_*.c")
    if getattr(args, 'drio', None):
        print(f"    3. Verify: drrun.exe -c winafl.dll -debug -target_module harness.exe ...")
    print()


def cmd_styles(args):
    """List available harness styles."""
    print(f"\n  Available Harness Styles:\n")
    for name, desc in HarnessGenerator.STYLES.items():
        print(f"    {name:16s}  {desc}")
    print(f"\n    auto              Auto-detect from analysis results (default)\n")


def cmd_pipe(args):
    """Process piped JSON input from winafl-target-finder.py."""
    data = read_pipe_input()
    if not data:
        print("  [!] No valid JSON on stdin.")
        print("  Usage: python winafl-target-finder.py harness target.dll --json | python winafl-harness-builder.py pipe")
        return

    # data could be a list of candidates or a single candidate
    candidates = data if isinstance(data, list) else [data]

    print(f"\n  Received {len(candidates)} candidates from pipeline.\n")

    # Process top N candidates
    limit = args.limit or 3
    for i, cand in enumerate(candidates[:limit]):
        offset = cand.get("offset", "0")
        binary = cand.get("binary", args.binary or "")
        name = cand.get("name", "unknown")

        if offset == "MANUAL" or not binary:
            continue

        print(f"  --- Candidate {i+1}: {name} (0x{offset}) ---")

        analyzer = DeepAnalyzer(binary, offset, arch=args.arch)
        results = analyzer.run_all()

        if results["is_safe"]:
            gen = HarnessGenerator(results, style=args.style)
            source = gen.generate()

            out_dir = args.out or "harness"
            os.makedirs(out_dir, exist_ok=True)
            out_file = os.path.join(out_dir, f"harness_{name}_{offset}.c")

            with open(out_file, "w") as f:
                f.write(source)
            print(f"  [OK] Generated: {out_file} (style: {gen.style})")
        else:
            print(f"  [SKIP] Not safe: {results['safety_errors']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="winafl-harness-builder",
        description="Automated harness generation & deep analysis for WinAFL",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Pipeline Examples:
          # Full automated pipeline
          %(prog)s full target.dll --offset 0x41040 --drio C:\\DynamoRIO --out harness\\

          # Just analyze a function
          %(prog)s analyze target.dll --offset 0x41040

          # Generate a specific harness style
          %(prog)s generate target.dll --offset 0x41040 --style buffer_parser

          # Pipe from target-finder
          python winafl-target-finder.py harness target.dll --json | %(prog)s pipe --binary target.dll

          # List available styles
          %(prog)s styles
        """)
    )

    # Global options
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64",
                        help="Target architecture (default: x64)")
    parser.add_argument("--json-out", action="store_true",
                        help="Also output analysis as JSON")
    parser.add_argument("--ghidra", metavar="HOST:PORT",
                        help="Connect to Ghidra MCP server (e.g. localhost:8192)")

    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Deep-analyze a target function")
    p_analyze.add_argument("binary", help="Target binary (EXE or DLL)")
    p_analyze.add_argument("--offset", required=True, help="Function offset (hex)")

    # generate
    p_gen = sub.add_parser("generate", help="Generate harness source code")
    p_gen.add_argument("binary", help="Target binary")
    p_gen.add_argument("--offset", required=True, help="Function offset (hex)")
    p_gen.add_argument("--style", default="auto",
                        choices=list(HarnessGenerator.STYLES.keys()) + ["auto"],
                        help="Harness style (default: auto-detect)")
    p_gen.add_argument("--out", help="Output directory (default: current dir)")
    p_gen.add_argument("--export-name", help="Export function name (for dll_export style)")
    p_gen.add_argument("--compile", action="store_true", help="Compile after generating")

    # validate
    p_val = sub.add_parser("validate", help="Pre-flight validation checks")
    p_val.add_argument("binary", help="Target binary")
    p_val.add_argument("--offset", required=True, help="Function offset (hex)")
    p_val.add_argument("--drio", help="DynamoRIO directory")
    p_val.add_argument("--harness-exe", help="Path to compiled harness")

    # full
    p_full = sub.add_parser("full", help="Full pipeline: analyze + generate + validate")
    p_full.add_argument("binary", help="Target binary")
    p_full.add_argument("--offset", required=True, help="Function offset (hex)")
    p_full.add_argument("--style", default="auto",
                        choices=list(HarnessGenerator.STYLES.keys()) + ["auto"])
    p_full.add_argument("--drio", help="DynamoRIO directory")
    p_full.add_argument("--out", help="Output directory (default: harness/)")

    # pipe
    p_pipe = sub.add_parser("pipe", help="Process piped input from winafl-target-finder.py")
    p_pipe.add_argument("--binary", help="Target binary (if not in piped data)")
    p_pipe.add_argument("--style", default="auto",
                        choices=list(HarnessGenerator.STYLES.keys()) + ["auto"])
    p_pipe.add_argument("--out", help="Output directory")
    p_pipe.add_argument("--limit", type=int, default=3,
                        help="Max candidates to process (default: 3)")

    # styles
    sub.add_parser("styles", help="List available harness styles")

    # auto (Ghidra-powered full automation)
    p_auto = sub.add_parser("auto", help="Fully automated: discover targets via Ghidra + generate harnesses")
    p_auto.add_argument("binary", help="Target binary")
    p_auto.add_argument("--style", default="auto",
                        choices=list(HarnessGenerator.STYLES.keys()) + ["auto"])
    p_auto.add_argument("--out", help="Output directory (default: harness/)")
    p_auto.add_argument("--limit", type=int, default=5,
                        help="Max candidates to process (default: 5)")
    p_auto.add_argument("--drio", help="DynamoRIO directory")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    commands = {
        "analyze": cmd_analyze,
        "generate": cmd_generate,
        "validate": cmd_validate,
        "full": cmd_full,
        "pipe": cmd_pipe,
        "styles": cmd_styles,
        "auto": cmd_auto,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
