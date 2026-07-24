#!/usr/bin/env python3
"""
WinAFL Target Finder - Automated Fuzzing Campaign Bootstrap Utility
Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)

Scans Windows executables and DLLs to identify promising fuzzing targets,
builds seed corpora, verifies DynamoRIO harnesses, and generates ready-to-run
afl-fuzz command lines with GPU acceleration.

Usage:
    python winafl-target-finder.py scan <path>           Scan directory for fuzzable targets
    python winafl-target-finder.py analyze <binary>      Deep-analyze a single binary
    python winafl-target-finder.py seeds <format> <out>  Build a minimal seed corpus
    python winafl-target-finder.py verify <binary> <offset> <drio_dir>   Test a harness
    python winafl-target-finder.py generate <binary> <offset> [options]  Generate launch cmd

Requirements:
    - Python 3.6+
    - dumpbin.exe (ships with Visual Studio)
    - DynamoRIO (for verify/generate commands)
"""

import os
import sys
import re
import subprocess
import struct
import argparse
import json
import glob
import io
from pathlib import Path
from collections import defaultdict

# Force UTF-8 output on Windows consoles
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# ============================================================================
# Configuration
# ============================================================================

# Imports that indicate file parsing behavior (high-value targets)
FILE_PARSING_IMPORTS = {
    "CreateFileA", "CreateFileW", "ReadFile", "ReadFileEx",
    "MapViewOfFile", "CreateFileMappingA", "CreateFileMappingW",
    "fopen", "fread", "fgets", "fclose", "fseek", "ftell",
    "_wfopen", "_read", "_open",
    "MultiByteToWideChar",  # often in parsers
}

# Imports that indicate complex data processing (memory manipulation = bugs)
DATA_PROCESSING_IMPORTS = {
    "malloc", "calloc", "realloc", "free",
    "HeapAlloc", "HeapReAlloc", "HeapFree",
    "VirtualAlloc", "VirtualFree",
    "memcpy", "memmove", "memset", "memcmp",
    "strcpy", "strncpy", "wcsncpy", "lstrcpyW",
    "sprintf", "swprintf", "vsprintf",
}

# Imports that indicate network activity (network fuzzing targets)
NETWORK_IMPORTS = {
    "recv", "recvfrom", "WSARecv",
    "send", "sendto", "WSASend",
    "accept", "listen", "bind", "connect",
    "socket", "WSASocketW",
}

# Known parser library patterns
PARSER_DLL_PATTERNS = [
    r"lib.*\.(dll|exe)$",          # libpng, libjpeg, libxml2, etc.
    r".*codec.*\.(dll|exe)$",      # avcodec, etc.
    r".*parse.*\.(dll|exe)$",      # parsers
    r".*decode.*\.(dll|exe)$",     # decoders
    r".*render.*\.(dll|exe)$",     # renderers
    r".*image.*\.(dll|exe)$",      # image processing
    r".*font.*\.(dll|exe)$",       # font parsers
    r".*pdf.*\.(dll|exe)$",        # PDF processing
    r".*xml.*\.(dll|exe)$",        # XML parsers
    r".*json.*\.(dll|exe)$",       # JSON parsers
    r".*zip.*\.(dll|exe)$",        # archive handlers
    r".*compress.*\.(dll|exe)$",   # compression
    r".*crypt.*\.(dll|exe)$",      # crypto
    r".*media.*\.(dll|exe)$",      # media handling
]

# File format to seed search patterns
SEED_SOURCES = {
    "pdf":  {"ext": ".pdf",  "dirs": [r"C:\Users\Public\Documents"], "min_size": 100, "max_size": 50000},
    "png":  {"ext": ".png",  "dirs": [r"C:\Windows\Web", r"C:\Windows\Resources"], "min_size": 50, "max_size": 10000},
    "jpg":  {"ext": ".jpg",  "dirs": [r"C:\Windows\Web", r"C:\Users\Public\Pictures"], "min_size": 50, "max_size": 10000},
    "jpeg": {"ext": ".jpeg", "dirs": [r"C:\Windows\Web", r"C:\Users\Public\Pictures"], "min_size": 50, "max_size": 10000},
    "bmp":  {"ext": ".bmp",  "dirs": [r"C:\Windows\Web", r"C:\Windows"], "min_size": 50, "max_size": 10000},
    "gif":  {"ext": ".gif",  "dirs": [r"C:\Windows\Web"], "min_size": 50, "max_size": 10000},
    "tiff": {"ext": ".tiff", "dirs": [r"C:\Windows\Web"], "min_size": 50, "max_size": 10000},
    "xml":  {"ext": ".xml",  "dirs": [r"C:\Windows\System32"], "min_size": 30, "max_size": 5000},
    "zip":  {"ext": ".zip",  "dirs": [r"C:\Users\Public"], "min_size": 50, "max_size": 20000},
    "mp3":  {"ext": ".mp3",  "dirs": [r"C:\Windows\Media"], "min_size": 100, "max_size": 50000},
    "wav":  {"ext": ".wav",  "dirs": [r"C:\Windows\Media"], "min_size": 100, "max_size": 50000},
    "avi":  {"ext": ".avi",  "dirs": [r"C:\Users\Public\Videos"], "min_size": 100, "max_size": 100000},
    "doc":  {"ext": ".doc",  "dirs": [r"C:\Users\Public\Documents"], "min_size": 100, "max_size": 50000},
    "ttf":  {"ext": ".ttf",  "dirs": [r"C:\Windows\Fonts"], "min_size": 1000, "max_size": 100000},
    "otf":  {"ext": ".otf",  "dirs": [r"C:\Windows\Fonts"], "min_size": 1000, "max_size": 100000},
}


# ============================================================================
# PE Header Analysis (no external deps)
# ============================================================================

class PEAnalyzer:
    """Lightweight PE parser to extract imports, exports, and metadata."""

    def __init__(self, filepath):
        self.filepath = filepath
        self.imports = defaultdict(list)
        self.exports = []
        self.is_64bit = False
        self.is_dll = False
        self.has_aslr = False
        self.has_dep = False
        self.has_cfg = False
        self.sections = []
        self._parse()

    def _parse(self):
        try:
            with open(self.filepath, "rb") as f:
                # DOS Header
                dos_sig = f.read(2)
                if dos_sig != b"MZ":
                    return

                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]

                # PE Signature
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b"PE\x00\x00":
                    return

                # COFF Header
                machine = struct.unpack("<H", f.read(2))[0]
                self.is_64bit = machine == 0x8664
                num_sections = struct.unpack("<H", f.read(2))[0]
                f.read(12)  # TimeDateStamp, PointerToSymbolTable, NumberOfSymbols
                opt_header_size = struct.unpack("<H", f.read(2))[0]
                characteristics = struct.unpack("<H", f.read(2))[0]
                self.is_dll = bool(characteristics & 0x2000)

                # Optional Header
                opt_start = f.tell()
                magic = struct.unpack("<H", f.read(2))[0]

                if magic == 0x20b:  # PE32+
                    f.seek(opt_start + 24)  # ImageBase offset for PE32+
                    f.seek(opt_start + 70)  # DllCharacteristics
                elif magic == 0x10b:  # PE32
                    f.seek(opt_start + 70)  # DllCharacteristics
                else:
                    return

                dll_chars = struct.unpack("<H", f.read(2))[0]
                self.has_aslr = bool(dll_chars & 0x0040)
                self.has_dep = bool(dll_chars & 0x0100)
                self.has_cfg = bool(dll_chars & 0x4000)

                # Section Headers
                f.seek(opt_start + opt_header_size)
                for _ in range(num_sections):
                    sec_data = f.read(40)
                    if len(sec_data) < 40:
                        break
                    name = sec_data[:8].rstrip(b'\x00').decode('ascii', errors='replace')
                    vsize = struct.unpack("<I", sec_data[8:12])[0]
                    self.sections.append({"name": name, "virtual_size": vsize})

        except (IOError, struct.error, OverflowError):
            pass

    def get_imports_via_dumpbin(self):
        """Use dumpbin to get detailed imports."""
        try:
            dumpbin = DUMPBIN_PATH or "dumpbin"
            result = subprocess.run(
                [dumpbin, "/imports", self.filepath],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                current_dll = None
                for line in result.stdout.splitlines():
                    line = line.strip()
                    # DLL name lines end with .dll
                    if line.lower().endswith(".dll"):
                        current_dll = line
                    # Import lines have function names
                    elif current_dll and line and not line.startswith("Section"):
                        parts = line.split()
                        if len(parts) >= 2:
                            func_name = parts[-1]
                            if func_name.isidentifier():
                                self.imports[current_dll].append(func_name)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return self.imports

    def get_exports_via_dumpbin(self):
        """Use dumpbin to get exports."""
        try:
            dumpbin = DUMPBIN_PATH or "dumpbin"
            result = subprocess.run(
                [dumpbin, "/exports", self.filepath],
                capture_output=True, text=True, timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                in_exports = False
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if "ordinal" in line.lower() and "name" in line.lower():
                        in_exports = True
                        continue
                    if in_exports and line:
                        parts = line.split()
                        if len(parts) >= 4:
                            self.exports.append({
                                "ordinal": parts[0],
                                "rva": parts[2],
                                "name": parts[3] if len(parts) > 3 else f"ordinal_{parts[0]}"
                            })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return self.exports


# ============================================================================
# Target Scoring
# ============================================================================

def score_target(pe, all_imports_flat):
    """Score a binary for fuzzing suitability (0-100)."""
    score = 0
    reasons = []

    # File parsing imports
    file_hits = FILE_PARSING_IMPORTS.intersection(all_imports_flat)
    if file_hits:
        score += min(len(file_hits) * 5, 30)
        reasons.append(f"File I/O: {', '.join(sorted(file_hits)[:5])}")

    # Data processing imports (memory ops = bugs)
    data_hits = DATA_PROCESSING_IMPORTS.intersection(all_imports_flat)
    if data_hits:
        score += min(len(data_hits) * 3, 20)
        reasons.append(f"Memory ops: {len(data_hits)} functions")

    # Network imports
    net_hits = NETWORK_IMPORTS.intersection(all_imports_flat)
    if net_hits:
        score += min(len(net_hits) * 4, 15)
        reasons.append(f"Network: {', '.join(sorted(net_hits)[:3])}")

    # DLL bonus (easier to harness)
    if pe.is_dll:
        score += 10
        reasons.append("DLL (easy to harness)")

    # Exports bonus for DLLs (more attack surface)
    if pe.exports:
        export_score = min(len(pe.exports) * 1, 10)
        score += export_score
        reasons.append(f"{len(pe.exports)} exports")

    # Name pattern matching
    basename = os.path.basename(pe.filepath).lower()
    for pattern in PARSER_DLL_PATTERNS:
        if re.match(pattern, basename):
            score += 10
            reasons.append(f"Name match: parser pattern")
            break

    # Penalty for mitigations (harder but still fuzzable)
    mitigations = []
    if pe.has_aslr:
        mitigations.append("ASLR")
    if pe.has_dep:
        mitigations.append("DEP")
    if pe.has_cfg:
        mitigations.append("CFG")
        score -= 5  # CFG makes exploitation harder

    if mitigations:
        reasons.append(f"Mitigations: {', '.join(mitigations)}")

    # Size of .text section (larger = more code = more bugs)
    for sec in pe.sections:
        if sec["name"] == ".text":
            text_kb = sec["virtual_size"] / 1024
            if text_kb > 500:
                score += 5
                reasons.append(f".text: {text_kb:.0f} KB")
            break

    return min(score, 100), reasons


# ============================================================================
# Target Scanning
# ============================================================================

def find_dumpbin():
    """Try to locate dumpbin.exe in the system."""
    try:
        result = subprocess.run(["where", "dumpbin"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return result.stdout.strip().splitlines()[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Search common VS paths
    vs_paths = glob.glob(r"C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe")
    if vs_paths:
        return vs_paths[0]

    return None

# Resolve dumpbin once at module load
DUMPBIN_PATH = find_dumpbin()


def scan_directory(scan_path, max_depth=3):
    """Scan a directory for fuzzable targets."""
    # Strip trailing quotes/backslashes (Windows cmd.exe escapes \" in "path\")
    scan_path = Path(str(scan_path).rstrip('"').rstrip('\\').rstrip('"'))

    if not scan_path.exists():
        print(f"\n  [-] Path does not exist: {scan_path}")
        return

    # If user passed a single file, scan its parent directory
    if scan_path.is_file():
        print(f"\n  [*] '{scan_path.name}' is a file — scanning parent directory: {scan_path.parent}")
        scan_path = scan_path.parent

    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Scanning: {scan_path}")
    print(f"{'='*70}\n")

    dumpbin = find_dumpbin()
    if dumpbin:
        print(f"  [+] dumpbin located: {dumpbin}")
    else:
        print(f"  [!] dumpbin not found (install VS Build Tools for deeper analysis)")
        print(f"      Falling back to PE header analysis only.\n")

    targets = []

    # Collect binaries
    binaries = []
    for ext in ("*.exe", "*.dll"):
        for f in scan_path.rglob(ext):
            # Respect max depth
            try:
                depth = len(f.relative_to(scan_path).parts) - 1
                if depth <= max_depth:
                    binaries.append(f)
            except ValueError:
                continue

    print(f"  [*] Found {len(binaries)} binaries to analyze...\n")

    for i, binary in enumerate(binaries):
        try:
            pe = PEAnalyzer(str(binary))

            # Get imports (use dumpbin if available, else just PE header data)
            all_imports_flat = set()
            if dumpbin:
                imports = pe.get_imports_via_dumpbin()
                for dll_imports in imports.values():
                    all_imports_flat.update(dll_imports)

            score, reasons = score_target(pe, all_imports_flat)

            if score >= 15:  # Only show interesting targets
                targets.append({
                    "path": str(binary),
                    "name": binary.name,
                    "score": score,
                    "reasons": reasons,
                    "is_64bit": pe.is_64bit,
                    "is_dll": pe.is_dll,
                    "exports_count": len(pe.exports) if pe.exports else 0,
                    "mitigations": {
                        "aslr": pe.has_aslr,
                        "dep": pe.has_dep,
                        "cfg": pe.has_cfg,
                    }
                })
        except Exception as e:
            continue

        # Progress
        if (i + 1) % 50 == 0:
            print(f"  [*] Analyzed {i + 1}/{len(binaries)}...")

    # Sort by score
    targets.sort(key=lambda x: x["score"], reverse=True)

    # Display results
    print(f"\n{'='*70}")
    print(f"  TOP FUZZING TARGETS (scored by attack surface)")
    print(f"{'='*70}\n")

    if not targets:
        print("  No suitable targets found in this directory.\n")
        return

    for i, t in enumerate(targets[:25]):
        arch = "x64" if t["is_64bit"] else "x86"
        kind = "DLL" if t["is_dll"] else "EXE"
        bar = "█" * (t["score"] // 5) + "░" * (20 - t["score"] // 5)

        print(f"  #{i+1:2d}  [{t['score']:3d}/100] {bar}  {t['name']}")
        print(f"       {kind} | {arch} | {t['path']}")
        for r in t["reasons"]:
            print(f"       • {r}")
        print()

    # Save results
    results_file = os.path.join(str(scan_path), "target_scan_results.json")
    try:
        with open(results_file, "w") as f:
            json.dump(targets, f, indent=2)
        print(f"  [+] Full results saved to: {results_file}")
    except IOError:
        results_file = "target_scan_results.json"
        with open(results_file, "w") as f:
            json.dump(targets, f, indent=2)
        print(f"  [+] Full results saved to: {results_file}")

    print(f"  [+] Total targets scored ≥15: {len(targets)}")
    print()

    return targets


def analyze_binary(binary_path):
    """Deep analysis of a single binary."""
    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Deep Analysis")
    print(f"  Binary: {binary_path}")
    print(f"{'='*70}\n")

    if not os.path.exists(binary_path):
        print(f"  [-] File not found: {binary_path}")
        return

    pe = PEAnalyzer(binary_path)

    print(f"  Architecture: {'x64' if pe.is_64bit else 'x86'}")
    print(f"  Type:         {'DLL' if pe.is_dll else 'EXE'}")
    print(f"  ASLR:         {'Yes' if pe.has_aslr else 'No'}")
    print(f"  DEP/NX:       {'Yes' if pe.has_dep else 'No'}")
    print(f"  CFG:          {'Yes' if pe.has_cfg else 'No'}")
    print()

    # Sections
    print(f"  Sections:")
    for sec in pe.sections:
        print(f"    {sec['name']:10s} {sec['virtual_size']:>10,d} bytes")
    print()

    # Imports
    imports = pe.get_imports_via_dumpbin()
    if imports:
        all_flat = set()
        for dll, funcs in imports.items():
            all_flat.update(funcs)

        print(f"  Imported DLLs: {len(imports)}")
        print(f"  Total imports: {len(all_flat)}")
        print()

        # Categorize
        file_hits = FILE_PARSING_IMPORTS.intersection(all_flat)
        data_hits = DATA_PROCESSING_IMPORTS.intersection(all_flat)
        net_hits = NETWORK_IMPORTS.intersection(all_flat)

        if file_hits:
            print(f"  📂 File I/O Functions ({len(file_hits)}):")
            for f in sorted(file_hits):
                print(f"       {f}")
            print()

        if data_hits:
            print(f"  🧠 Memory/Data Functions ({len(data_hits)}):")
            for f in sorted(data_hits):
                print(f"       {f}")
            print()

        if net_hits:
            print(f"  🌐 Network Functions ({len(net_hits)}):")
            for f in sorted(net_hits):
                print(f"       {f}")
            print()

    # Exports
    exports = pe.get_exports_via_dumpbin()
    if exports:
        print(f"  Exported Functions ({len(exports)}):")
        # Highlight functions that look like parsers
        parser_keywords = ["parse", "read", "load", "decode", "open", "process", "import", "extract", "init"]
        highlighted = []
        normal = []
        for exp in exports:
            name = exp.get("name", "")
            if any(kw in name.lower() for kw in parser_keywords):
                highlighted.append(exp)
            else:
                normal.append(exp)

        if highlighted:
            print(f"\n  ⭐ HIGH-VALUE EXPORTS (potential target functions):")
            for exp in highlighted:
                print(f"       0x{exp['rva']}  {exp['name']}")

        if normal and len(normal) <= 30:
            print(f"\n  Other exports:")
            for exp in normal:
                print(f"       0x{exp['rva']}  {exp['name']}")
        elif normal:
            print(f"\n  ... and {len(normal)} other exports (use dumpbin /exports for full list)")

    # Score
    all_flat = set()
    for funcs in imports.values():
        all_flat.update(funcs)
    score, reasons = score_target(pe, all_flat)

    print(f"\n  {'='*50}")
    print(f"  FUZZ SCORE: {score}/100")
    for r in reasons:
        print(f"    • {r}")
    print(f"  {'='*50}\n")


# ============================================================================
# Seed Corpus Builder
# ============================================================================

def build_seed_corpus(fmt, output_dir, afl_tmin_path=None, drio_dir=None, target_cmd=None):
    """Build and optionally minimize a seed corpus for a given file format."""
    fmt = fmt.lower().lstrip(".")

    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Seed Corpus Builder")
    print(f"  Format: .{fmt}")
    print(f"{'='*70}\n")

    if fmt not in SEED_SOURCES:
        print(f"  [-] Unknown format '.{fmt}'. Supported formats:")
        for k in sorted(SEED_SOURCES.keys()):
            print(f"       .{k}")
        print()
        print(f"  Tip: Manually create a folder with small sample files of your target format.")
        return

    config = SEED_SOURCES[fmt]
    os.makedirs(output_dir, exist_ok=True)

    found_files = []
    for search_dir in config["dirs"]:
        if not os.path.exists(search_dir):
            continue
        for root, dirs, files in os.walk(search_dir):
            # Don't recurse too deep
            depth = root.replace(search_dir, "").count(os.sep)
            if depth > 3:
                continue
            for f in files:
                if f.lower().endswith(config["ext"]):
                    full = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(full)
                        if config["min_size"] <= sz <= config["max_size"]:
                            found_files.append((full, sz))
                    except OSError:
                        continue

    print(f"  [*] Searched {len(config['dirs'])} system directories")
    print(f"  [+] Found {len(found_files)} candidate files (size {config['min_size']}-{config['max_size']} bytes)")
    print()

    if not found_files:
        print(f"  [!] No suitable files found. Creating a minimal synthetic seed...")
        # Create a minimal valid-ish file
        seed_path = os.path.join(output_dir, f"minimal.{fmt}")
        _create_minimal_seed(fmt, seed_path)
        print(f"  [+] Created: {seed_path}")
        return

    # Sort by size (prefer smaller) and take top 20
    found_files.sort(key=lambda x: x[1])
    selected = found_files[:20]

    print(f"  [*] Copying {len(selected)} smallest files to {output_dir}...")
    for i, (src, sz) in enumerate(selected):
        dst = os.path.join(output_dir, f"seed_{i:03d}{config['ext']}")
        try:
            with open(src, "rb") as fin, open(dst, "wb") as fout:
                fout.write(fin.read())
            print(f"       {dst} ({sz:,d} bytes)")
        except IOError as e:
            print(f"       [!] Failed to copy {src}: {e}")

    # Minimize with afl-tmin if available
    if afl_tmin_path and drio_dir and target_cmd:
        print(f"\n  [*] Minimizing seeds with afl-tmin...")
        min_dir = output_dir + "_minimized"
        os.makedirs(min_dir, exist_ok=True)

        for seed_file in os.listdir(output_dir):
            seed_path = os.path.join(output_dir, seed_file)
            min_path = os.path.join(min_dir, seed_file)
            cmd = f'"{afl_tmin_path}" -D "{drio_dir}" -t 5000 -i "{seed_path}" -o "{min_path}" -- {target_cmd}'
            print(f"       Minimizing: {seed_file}")
            try:
                subprocess.run(cmd, shell=True, timeout=30, capture_output=True)
            except subprocess.TimeoutExpired:
                print(f"       [!] Timeout on {seed_file}, keeping original")
                import shutil
                shutil.copy2(seed_path, min_path)

        print(f"\n  [+] Minimized corpus: {min_dir}")
    else:
        print(f"\n  Tip: To minimize seeds, provide --afl-tmin, --drio-dir, and --target-cmd")

    print(f"\n  [+] Seed corpus ready: {output_dir}")
    print(f"  [+] Total seeds: {len(selected)}\n")


def _create_minimal_seed(fmt, path):
    """Create a minimal but structurally valid seed file."""
    seeds = {
        "pdf": b"%PDF-1.0\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 3 3]>>endobj\nxref\n0 4\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF",
        "png": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,  # PNG signature
                      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,  # IHDR chunk
                      0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  # 1x1
                      0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
                      0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
                      0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
                      0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC,
                      0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
                      0x44, 0xAE, 0x42, 0x60, 0x82]),
        "bmp": (b"BM" + struct.pack("<IHHIIIIHHIIIIII",
                                     70, 0, 0, 54, 40,
                                     1, 1, 1, 24, 0,
                                     16, 0, 0, 0, 0) + b"\xFF\xFF\xFF\x00"),
        "xml": b'<?xml version="1.0"?>\n<root><item attr="val">data</item></root>',
        "json": b'{"key": "value", "num": 42, "arr": [1, 2, 3]}',
        "zip": bytes([0x50, 0x4B, 0x05, 0x06] + [0x00] * 18),  # Empty ZIP end-of-central-directory
        "wav": b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xAC\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00",
    }

    data = seeds.get(fmt, b"FUZZ" + bytes(range(256)))
    with open(path, "wb") as f:
        f.write(data)


# ============================================================================
# Harness Discovery (automated target function identification)
# ============================================================================

# Functions that indicate a candidate is a file-parsing entry point
ENTRY_POINT_CALLS = {
    # File open/read functions — the candidate should call these
    "CreateFileA", "CreateFileW", "CreateFileExW",
    "ReadFile", "ReadFileEx",
    "MapViewOfFile", "CreateFileMappingW", "CreateFileMappingA",
    "fopen", "_wfopen", "fread", "_read", "fgets",
    "fclose", "CloseHandle",  # must close handle for WinAFL
}

# Functions that DISQUALIFY a candidate (won't return normally)
DISQUALIFYING_CALLS = {
    "ExitProcess", "TerminateProcess", "abort", "exit", "_exit",
    "FatalAppExitA", "FatalAppExitW", "RaiseException",
}

# Keywords in export names that suggest parsing/processing
PARSER_EXPORT_KEYWORDS = [
    "parse", "read", "load", "open", "decode", "import", "extract",
    "process", "handle", "analyze", "convert", "transform", "render",
    "inflate", "decompress", "unpack", "deserialize", "unmarshal",
    "scan", "lex", "tokenize", "eval", "execute", "interpret",
    "create_from", "init_from", "from_file", "from_stream", "from_buffer",
    "read_file", "load_file", "open_file", "parse_file",
    "readimage", "loadimage", "openimage", "decodeimage",
    "input", "ingest", "consume", "accept",
]


def find_harness_candidates(binary_path, drio_dir=None):
    """Identify candidate target functions and offsets for WinAFL harnessing."""
    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Harness Discovery")
    print(f"  Binary: {binary_path}")
    print(f"{'='*70}\n")

    if not os.path.exists(binary_path):
        print(f"  [-] File not found: {binary_path}")
        return

    pe = PEAnalyzer(binary_path)
    module_name = os.path.basename(binary_path)
    is_dll = pe.is_dll

    print(f"  Architecture: {'x64' if pe.is_64bit else 'x86'}")
    print(f"  Type:         {'DLL' if is_dll else 'EXE'}")
    print()

    candidates = []

    # ---- Strategy 1: Export analysis (DLLs) ----
    if is_dll:
        print(f"  [*] Strategy 1: Analyzing exported functions...")
        exports = pe.get_exports_via_dumpbin()
        if exports:
            for exp in exports:
                name = exp.get("name", "")
                rva = exp.get("rva", "0")
                score = 0
                reasons = []

                # Score by name matching — two tiers
                name_lower = name.lower()

                # Tier 1: High-value file I/O entry points (best WinAFL targets)
                tier1_keywords = [
                    "fromfile", "from_file", "fromstream", "from_stream",
                    "loadimage", "load_image", "readfile", "read_file",
                    "openfile", "open_file", "parsefile", "parse_file",
                    "frombuffer", "from_buffer", "loadfrom", "readfrom",
                    "createfrom", "create_from", "initfrom", "init_from",
                ]
                tier1_hit = False
                for kw in tier1_keywords:
                    if kw in name_lower:
                        score += 25
                        reasons.append(f"HIGH: File I/O entry ('{kw}')")
                        tier1_hit = True
                        break

                # Tier 2: General parser/processing keywords
                if not tier1_hit:
                    for kw in PARSER_EXPORT_KEYWORDS:
                        if kw in name_lower:
                            score += 15
                            reasons.append(f"Name contains '{kw}'")
                            break

                # Penalize internal/helper-looking functions
                if name.startswith("_") and not name.startswith("__"):
                    score -= 5
                if any(x in name_lower for x in ["internal", "private", "helper", "util", "debug", "test", "log"]):
                    score -= 10

                # Bonus for functions that look like entry points
                if any(x in name_lower for x in ["main", "entry", "start", "run", "exec"]):
                    score += 5
                    reasons.append("Entry-point pattern")

                if score > 0:
                    candidates.append({
                        "name": name,
                        "offset": rva,
                        "score": score,
                        "reasons": reasons,
                        "source": "export",
                    })
            print(f"       Found {len(exports)} exports, {len(candidates)} look promising")
        else:
            print(f"       No exports found (or dumpbin unavailable)")
        print()

    # ---- Strategy 2: Disassembly analysis ----
    print(f"  [*] Strategy 2: Disassembly analysis (tracing file I/O call sites)...")
    call_site_candidates = _find_call_sites(binary_path, pe.is_64bit)
    candidates.extend(call_site_candidates)
    print(f"       Found {len(call_site_candidates)} functions referencing file I/O")
    print()

    # ---- Strategy 3: String references ----
    print(f"  [*] Strategy 3: Scanning for file-format string references...")
    string_candidates = _find_string_refs(binary_path)
    candidates.extend(string_candidates)
    print(f"       Found {len(string_candidates)} functions near format-related strings")
    print()

    # Deduplicate by offset — take max score, merge unique reasons
    seen_offsets = {}
    for c in candidates:
        key = c["offset"]
        if key not in seen_offsets:
            seen_offsets[key] = c
        else:
            existing = seen_offsets[key]
            existing["score"] = max(existing["score"], c["score"])
            for r in c["reasons"]:
                if r not in existing["reasons"]:
                    existing["reasons"].append(r)
            if c["name"] and not existing["name"]:
                existing["name"] = c["name"]
    candidates = list(seen_offsets.values())

    # Sort by score
    candidates.sort(key=lambda x: x["score"], reverse=True)

    # Display
    print(f"  {'='*60}")
    print(f"  CANDIDATE TARGET FUNCTIONS (ranked by suitability)")
    print(f"  {'='*60}\n")

    if not candidates:
        print("  No candidates found. Try manual analysis with IDA/Ghidra.")
        print("  Look for functions that:")
        print("    1. Open a file (CreateFileW, fopen)")
        print("    2. Read and process data (ReadFile, fread)")
        print("    3. Close the handle (CloseHandle, fclose)")
        print("    4. Return normally (no ExitProcess)")
        return

    top = candidates[:15]
    for i, c in enumerate(top):
        bar = "#" * min(c["score"] // 3, 20)
        name_str = c["name"] if c["name"] else f"sub_{c['offset']}"
        print(f"  #{i+1:2d}  [Score: {c['score']:3d}]  0x{c['offset']}  {name_str}")
        for r in c["reasons"]:
            print(f"       + {r}")
        print()

    # Generate verify/generate commands for top candidate
    best = top[0]
    offset = best["offset"]
    print(f"  {'='*60}")
    print(f"  RECOMMENDED NEXT STEPS")
    print(f"  {'='*60}\n")
    print(f"  Best candidate: 0x{offset}  ({best['name'] or 'unnamed'})\n")

    if drio_dir:
        print(f"  1. Verify the harness:")
        print(f"     python winafl-target-finder.py verify \"{binary_path}\" {offset} \"{drio_dir}\"\n")
        print(f"  2. If verification passes, generate the launch command:")
        print(f"     python winafl-target-finder.py generate \"{binary_path}\" {offset} --drio \"{drio_dir}\"\n")
    else:
        print(f"  1. Verify the harness:")
        print(f"     python winafl-target-finder.py verify \"{binary_path}\" {offset} <DynamoRIO_dir>\n")
        print(f"  2. Generate the launch command:")
        print(f"     python winafl-target-finder.py generate \"{binary_path}\" {offset} --drio <DynamoRIO_dir>\n")

    print(f"  If the top candidate doesn't work, try the next ones in the list.\n")

    return candidates


def _find_call_sites(binary_path, is_64bit):
    """Use dumpbin /disasm to find functions that reference file I/O APIs."""
    candidates = []

    try:
        dumpbin = DUMPBIN_PATH or "dumpbin"
        # Use dumpbin /disasm — this can be large, so we limit output
        result = subprocess.run(
            [dumpbin, "/disasm", binary_path],
            capture_output=True, text=True, timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode != 0:
            return candidates

        lines = result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired, MemoryError):
        return candidates

    # Parse disassembly to find functions that call file I/O
    current_func_offset = None
    current_func_name = None
    file_io_calls = set()
    disqualified = False
    close_calls = False

    for line in lines:
        stripped = line.strip()

        # Function header: "  0000000140001000: 48 89 5C 24 08     mov     qword ptr [rsp+8],rbx"
        # or label: "Module!FuncName:"
        # New function detected by address gap or label
        func_match = re.match(r'^\s*([0-9A-Fa-f]{8,16}):', stripped)
        label_match = re.match(r'^(\w+!)?(\w+):$', stripped)

        if label_match:
            # Save previous function
            if current_func_offset and file_io_calls and not disqualified:
                score = len(file_io_calls) * 10
                if close_calls:
                    score += 15  # Bonus: closes handles (required for WinAFL)
                reasons = [f"Calls: {', '.join(sorted(file_io_calls))}"]
                if close_calls:
                    reasons.append("Closes file handles (WinAFL compatible)")
                candidates.append({
                    "name": current_func_name or "",
                    "offset": current_func_offset,
                    "score": score,
                    "reasons": reasons,
                    "source": "disasm",
                })

            current_func_name = label_match.group(2)
            current_func_offset = None
            file_io_calls = set()
            disqualified = False
            close_calls = False

        elif func_match and current_func_offset is None:
            # Capture the first address as the function offset
            addr = func_match.group(1)
            # Convert to RVA (strip image base)
            try:
                addr_int = int(addr, 16)
                if is_64bit and addr_int > 0x140000000:
                    current_func_offset = format(addr_int - 0x140000000, 'X')
                elif not is_64bit and addr_int > 0x10000000:
                    current_func_offset = format(addr_int - 0x10000000, 'X')
                else:
                    current_func_offset = addr
            except ValueError:
                current_func_offset = addr

        # Check for CALL instructions to file I/O functions
        if "call" in stripped.lower():
            for api in ENTRY_POINT_CALLS:
                if api in stripped:
                    file_io_calls.add(api)
                    break
            for api in DISQUALIFYING_CALLS:
                if api in stripped:
                    disqualified = True
                    break
            if "CloseHandle" in stripped or "fclose" in stripped:
                close_calls = True

    # Don't forget the last function
    if current_func_offset and file_io_calls and not disqualified:
        score = len(file_io_calls) * 10
        if close_calls:
            score += 15
        reasons = [f"Calls: {', '.join(sorted(file_io_calls))}"]
        if close_calls:
            reasons.append("Closes file handles (WinAFL compatible)")
        candidates.append({
            "name": current_func_name or "",
            "offset": current_func_offset,
            "score": score,
            "reasons": reasons,
            "source": "disasm",
        })

    return candidates


def _find_string_refs(binary_path):
    """Scan for format-related strings that suggest parsing logic nearby."""
    candidates = []

    # Common format magic / header strings
    format_strings = [
        b"%PDF", b"PNG", b"JFIF", b"GIF8", b"RIFF", b"BM",
        b"PK\x03\x04",  # ZIP
        b"<?xml", b"<!DOCTYPE",
        b"MZ",  # PE
        b"\xff\xd8\xff",  # JPEG
        b"OggS",
        b"fLaC",
        b"ID3",  # MP3
    ]

    try:
        dumpbin = DUMPBIN_PATH or "dumpbin"
        result = subprocess.run(
            [dumpbin, "/rawdata:bytes", "/section:.rdata", binary_path],
            capture_output=True, text=True, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            rdata = result.stdout
            for fmt_str in format_strings:
                try:
                    search = fmt_str.decode('ascii', errors='replace')
                    if search in rdata:
                        candidates.append({
                            "name": f"(near string '{search.strip()}')",
                            "offset": "MANUAL",
                            "score": 5,
                            "reasons": [f"Binary contains format string: '{search.strip()}'"],
                            "source": "strings",
                        })
                except Exception:
                    continue
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return candidates


# ============================================================================
# Harness Verification
# ============================================================================

def verify_harness(binary, offset, drio_dir, nargs=2, iterations=10):
    """Test a harness with DynamoRIO debug mode."""
    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Harness Verification")
    print(f"{'='*70}\n")

    # Find drrun.exe
    drrun = os.path.join(drio_dir, "bin64", "drrun.exe")
    if not os.path.exists(drrun):
        drrun = os.path.join(drio_dir, "bin32", "drrun.exe")
    if not os.path.exists(drrun):
        print(f"  [-] drrun.exe not found in {drio_dir}")
        print(f"      Expected at: {drio_dir}\\bin64\\drrun.exe")
        return False

    # Find winafl.dll
    winafl_dll = None
    for candidate in [
        os.path.join(os.path.dirname(binary), "winafl.dll"),
        os.path.join("bin", "Release", "winafl.dll"),
        "winafl.dll",
    ]:
        if os.path.exists(candidate):
            winafl_dll = os.path.abspath(candidate)
            break

    if not winafl_dll:
        print(f"  [!] winafl.dll not found. Build WinAFL first.")
        print(f"      Will run drrun in debug mode without winafl.dll")
        winafl_dll = "winafl.dll"

    module_name = os.path.basename(binary)

    # Create a temp input file
    temp_input = "harness_test_input.bin"
    with open(temp_input, "wb") as f:
        f.write(b"A" * 64)

    cmd = (
        f'"{drrun}" -c "{winafl_dll}" '
        f'-debug -target_module {module_name} -target_offset 0x{offset} '
        f'-fuzz_iterations {iterations} -nargs {nargs} '
        f'-- "{binary}" "{temp_input}"'
    )

    print(f"  [*] Running harness verification:")
    print(f"      {cmd}\n")

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=30
        )

        print(f"  Exit code: {result.returncode}")
        print()

        # Check for afl.log
        log_files = glob.glob("afl.*.log") + (["afl.log"] if os.path.exists("afl.log") else [])
        if log_files:
            print(f"  [+] AFL log found: {log_files[0]}")
            with open(log_files[0], "r") as f:
                content = f.read()
            print(f"  Log contents:\n")
            for line in content.splitlines()[-20:]:
                print(f"    {line}")
            print()

            if "Everything appears to be running normally" in content:
                print(f"  ✅ HARNESS VERIFIED SUCCESSFULLY")
                return True
            elif "crash" in content.lower() or "exception" in content.lower():
                print(f"  ❌ HARNESS CRASHED - check the target function")
                return False
            else:
                print(f"  ⚠️  Inconclusive - review log manually")
                return False
        else:
            print(f"  [!] No afl.log generated")
            if result.stderr:
                print(f"  stderr:\n{result.stderr[:500]}")
            return False

    except subprocess.TimeoutExpired:
        print(f"  [!] Harness timed out after 30 seconds")
        return False
    finally:
        if os.path.exists(temp_input):
            os.remove(temp_input)


# ============================================================================
# Launch Command Generator
# ============================================================================

def generate_launch_command(binary, offset, drio_dir=None, input_dir="in",
                            output_dir="out", timeout=2000, gpu=True,
                            coverage_module=None, fuzz_iterations=5000,
                            winafl_dll=None):
    """Generate a ready-to-run afl-fuzz command."""
    print(f"\n{'='*70}")
    print(f"  WinAFL Target Finder - Launch Command Generator")
    print(f"{'='*70}\n")

    module_name = os.path.basename(binary)
    if not coverage_module:
        coverage_module = module_name

    afl_fuzz = os.path.join("bin", "Release", "afl-fuzz.exe")
    if not os.path.exists(afl_fuzz):
        afl_fuzz = "afl-fuzz.exe"

    parts = [f'"{afl_fuzz}"']

    if gpu:
        parts.append("-G")

    parts.extend([
        f'-i {input_dir}',
        f'-o {output_dir}',
        f'-t {timeout}',
    ])

    if drio_dir:
        parts.append(f'-D "{drio_dir}"')

    if winafl_dll:
        parts.append(f'-w "{winafl_dll}"')

    parts.append("--")

    # DynamoRIO instrumentation options
    parts.extend([
        f'-target_module {module_name}',
        f'-target_offset 0x{offset}',
        f'-coverage_module {coverage_module}',
        f'-fuzz_iterations {fuzz_iterations}',
        f'-nargs 2',
    ])

    parts.append("--")
    parts.append(f'"{binary}" @@')

    cmd = " ".join(parts)

    print(f"  Generated command:\n")
    print(f"    {cmd}\n")

    # Pre-flight checklist
    print(f"  Pre-flight checklist:")
    checks = [
        (os.path.exists(binary), f"  ✅ Target binary exists: {binary}",
                                  f"  ❌ Target not found: {binary}"),
        (os.path.exists(input_dir), f"  ✅ Input directory exists: {input_dir}",
                                     f"  ❌ Create input dir: mkdir {input_dir}"),
        (not os.path.exists(output_dir) or len(os.listdir(output_dir)) == 0,
         f"  ✅ Output directory is clean",
         f"  ⚠️  Output dir exists and is not empty: {output_dir}"),
    ]

    if drio_dir:
        drrun = os.path.join(drio_dir, "bin64", "drrun.exe")
        checks.append(
            (os.path.exists(drrun),
             f"  ✅ DynamoRIO found: {drrun}",
             f"  ❌ DynamoRIO not found at: {drrun}")
        )

    seeds = glob.glob(os.path.join(input_dir, "*")) if os.path.exists(input_dir) else []
    checks.append(
        (len(seeds) > 0,
         f"  ✅ Seeds found: {len(seeds)} files",
         f"  ❌ No seeds! Add sample files to {input_dir}/")
    )

    all_ok = True
    for ok, good_msg, bad_msg in checks:
        print(good_msg if ok else bad_msg)
        if not ok:
            all_ok = False

    print()

    if all_ok:
        print(f"  🚀 Ready to fuzz! Copy and run the command above.")
    else:
        print(f"  ⚠️  Fix the issues above before fuzzing.")

    print()
    return cmd


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="winafl-target-finder",
        description="Automated fuzzing campaign bootstrap utility for WinAFL + GPU",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan "C:\\Program Files\\SomeApp"
  %(prog)s analyze target.dll
  %(prog)s seeds png ./in
  %(prog)s verify target.exe 12A40 C:\\DynamoRIO
  %(prog)s generate target.exe 12A40 --drio C:\\DynamoRIO --gpu
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    sp_scan = subparsers.add_parser("scan", help="Scan directory for fuzzable targets")
    sp_scan.add_argument("path", help="Directory to scan")
    sp_scan.add_argument("--depth", type=int, default=3, help="Max recursion depth")

    # analyze
    sp_analyze = subparsers.add_parser("analyze", help="Deep-analyze a single binary")
    sp_analyze.add_argument("binary", help="Path to EXE or DLL")

    # seeds
    sp_seeds = subparsers.add_parser("seeds", help="Build a minimal seed corpus")
    sp_seeds.add_argument("format", help="File format (e.g., png, pdf, xml)")
    sp_seeds.add_argument("output", help="Output directory for seeds")
    sp_seeds.add_argument("--afl-tmin", help="Path to afl-tmin.exe for minimization")
    sp_seeds.add_argument("--drio-dir", help="DynamoRIO directory (for afl-tmin)")
    sp_seeds.add_argument("--target-cmd", help="Target command line (for afl-tmin)")

    # harness
    sp_harness = subparsers.add_parser("harness", help="Find candidate target functions for WinAFL harnessing")
    sp_harness.add_argument("binary", help="Target EXE or DLL to analyze")
    sp_harness.add_argument("--drio", help="DynamoRIO directory (for generated verify commands)")

    # verify
    sp_verify = subparsers.add_parser("verify", help="Verify a DynamoRIO harness")
    sp_verify.add_argument("binary", help="Target binary")
    sp_verify.add_argument("offset", help="Target function offset (hex, no 0x prefix)")
    sp_verify.add_argument("drio_dir", help="DynamoRIO directory")
    sp_verify.add_argument("--nargs", type=int, default=2, help="Number of arguments")
    sp_verify.add_argument("--iterations", type=int, default=10, help="Test iterations")

    # generate
    sp_gen = subparsers.add_parser("generate", help="Generate afl-fuzz launch command")
    sp_gen.add_argument("binary", help="Target binary")
    sp_gen.add_argument("offset", help="Target function offset (hex, no 0x prefix)")
    sp_gen.add_argument("--drio", help="DynamoRIO directory")
    sp_gen.add_argument("--input", default="in", help="Input seed directory")
    sp_gen.add_argument("--output", default="out", help="Output directory")
    sp_gen.add_argument("--timeout", type=int, default=2000, help="Timeout in ms")
    sp_gen.add_argument("--gpu", action="store_true", default=True, help="Enable GPU (default)")
    sp_gen.add_argument("--no-gpu", action="store_true", help="Disable GPU")
    sp_gen.add_argument("--coverage-module", help="Module to collect coverage for")
    sp_gen.add_argument("--winafl-dll", help="Path to winafl.dll")
    sp_gen.add_argument("--fuzz-iterations", type=int, default=5000)

    # all
    sp_all = subparsers.add_parser("all", help="Run the entire 4-step fuzzing pipeline automatically")
    sp_all.add_argument("binary", help="Target EXE or DLL to fuzz")
    sp_all.add_argument("format", help="Input format for seeds (e.g., pdf, png)")
    sp_all.add_argument("--drio", help="DynamoRIO directory", required=True)
    sp_all.add_argument("--out", default="out", help="Output directory")
    sp_all.add_argument("--gen-harness", action="store_true", help="Also generate harness C code")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "scan":
        scan_directory(args.path, args.depth)

    elif args.command == "analyze":
        analyze_binary(args.binary)

    elif args.command == "harness":
        find_harness_candidates(args.binary, drio_dir=args.drio)

    elif args.command == "seeds":
        build_seed_corpus(
            args.format, args.output,
            afl_tmin_path=getattr(args, 'afl_tmin', None),
            drio_dir=getattr(args, 'drio_dir', None),
            target_cmd=getattr(args, 'target_cmd', None),
        )

    elif args.command == "verify":
        verify_harness(args.binary, args.offset, args.drio_dir,
                       nargs=args.nargs, iterations=args.iterations)

    elif args.command == "generate":
        generate_launch_command(
            args.binary, args.offset,
            drio_dir=args.drio,
            input_dir=args.input,
            output_dir=args.output,
            timeout=args.timeout,
            gpu=not args.no_gpu,
            coverage_module=args.coverage_module,
            fuzz_iterations=args.fuzz_iterations,
            winafl_dll=args.winafl_dll,
        )

    elif args.command == "all":
        print(f"\n======================================================================")
        print(f"  WinAFL Target Finder - AUTO-PILOT MODE")
        print(f"======================================================================\n")
        
        # Step 1: Find best offset
        print(f"[*] STEP 1: Analyzing {args.binary} for the best target offset...")
        candidates = find_harness_candidates(args.binary, drio_dir=args.drio)
        if not candidates:
            print(f"[-] No suitable targets found. Aborting.")
            return
        
        best_candidate = candidates[0]
        best_offset = best_candidate.get("offset")
        if best_offset == "MANUAL":
            best_offset = candidates[1].get("offset") if len(candidates) > 1 else None
            
        if not best_offset:
            print(f"[-] Could not determine an exact offset automatically. Aborting.")
            return
            
        print(f"[+] Selected best target: {best_candidate.get('name')} at offset 0x{best_offset}\n")

        # Step 2: Generate Harness Code
        print(f"[*] STEP 2: Writing Harness C Code...")
        harness_builder = "winafl-harness-builder.py"
        if os.path.exists(harness_builder) or os.path.exists(os.path.join(os.path.dirname(__file__), harness_builder)):
            harness_path = harness_builder if os.path.exists(harness_builder) else os.path.join(os.path.dirname(__file__), harness_builder)
            cmd = f'python "{harness_path}" generate "{args.binary}" --offset {best_offset}'
            print(f"    Running: {cmd}")
            # Try to pipe the JSON exactly as they would manually
            try:
                # Capture just the code to disk
                import tempfile
                proc = subprocess.run(f'python "{harness_path}" generate "{args.binary}" --offset {best_offset} > auto_harness.c', shell=True)
                print(f"[+] Wrote auto_harness.c to current directory.\n")
            except Exception as e:
                print(f"[-] Failed to invoke harness builder: {e}\n")
        else:
            print(f"[-] winafl-harness-builder.py not found. Skipping harness generation.\n")

        # Step 3: Build Seed Corpus
        print(f"[*] STEP 3: Building seed corpus for '{args.format}'...")
        in_dir = os.path.join(args.out, "in_dir")
        build_seed_corpus(args.format, in_dir)

        # Step 4: Generate Launch Command
        out_dir = os.path.join(args.out, "out_dir")
        print(f"[*] STEP 4: Generating Fuzzer Launch Command...\n")
        generate_launch_command(
            args.binary, best_offset,
            drio_dir=args.drio,
            input_dir=in_dir,
            output_dir=out_dir,
            timeout=2000,
            gpu=True,
            coverage_module=None,
            fuzz_iterations=5000,
            winafl_dll=None,
        )
        print(f"[+] Auto-Pilot complete. Compile auto_harness.c and run the command above!")


if __name__ == "__main__":
    main()
