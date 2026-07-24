#!/usr/bin/env python3
"""
Ghidra Bridge — Protocol-agnostic client for Ghidra MCP servers.
Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)

Supports:
  - GhydraMCP (starsong-consulting) — HATEOAS REST API [PRIMARY]
  - GhidraMCP (LaurieWired) — HTTP API
  - GhidrAssistMCP (jtang613) — HTTP API

Usage:
    from ghidra_bridge import GhidraClient

    ghidra = GhidraClient("localhost", 8192)
    if ghidra.connect():
        funcs = ghidra.list_functions(limit=50)
        code  = ghidra.decompile("GdipLoadImageFromFile")
        graph = ghidra.get_callgraph("main", depth=3)

CLI test:
    python ghidra_bridge.py --test localhost:8192
    python ghidra_bridge.py --list-functions localhost:8192
    python ghidra_bridge.py --decompile main localhost:8192
"""

import sys
import io
import json
import argparse
import textwrap
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import quote, urlencode

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


# ============================================================================
# Data Classes
# ============================================================================

class FunctionInfo:
    """Represents a function from Ghidra analysis."""
    __slots__ = ("name", "address", "signature", "size", "entry_point",
                 "calling_convention", "return_type", "parameters", "is_thunk")

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))

    def __repr__(self):
        return f"Function({self.name} @ 0x{self.address or '?'}, sig={self.signature})"

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class XRef:
    """Cross-reference."""
    __slots__ = ("from_addr", "to_addr", "ref_type", "from_func", "to_func")

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class Variable:
    """Function variable."""
    __slots__ = ("name", "data_type", "storage", "size", "is_parameter")

    def __init__(self, **kwargs):
        for k in self.__slots__:
            setattr(self, k, kwargs.get(k))

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ============================================================================
# Ghidra HTTP Client (GhydraMCP REST API)
# ============================================================================

class GhidraClient:
    """
    Protocol-agnostic Ghidra client.
    Primary backend: GhydraMCP HATEOAS REST API.
    Fallback: raw HTTP to GhidraMCP or GhidrAssistMCP.
    """

    def __init__(self, host="localhost", port=8192, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self.connected = False
        self.server_type = None  # "ghydra", "ghidramcp", "ghidrassist"
        self.program_name = None

    # ----------------------------------------------------------------
    # HTTP helpers
    # ----------------------------------------------------------------

    def _get(self, path, params=None):
        """Send GET request, return parsed JSON or None."""
        url = f"{self.base_url}{path}"
        if params:
            url += "?" + urlencode(params)
        try:
            req = Request(url, headers={"Accept": "application/json"})
            with urlopen(req, timeout=self.timeout) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except (URLError, HTTPError, json.JSONDecodeError, TimeoutError) as e:
            return None

    def _post(self, path, body=None):
        """Send POST request with JSON body."""
        url = f"{self.base_url}{path}"
        data = json.dumps(body or {}).encode("utf-8")
        try:
            req = Request(url, data=data, method="POST",
                          headers={"Content-Type": "application/json",
                                   "Accept": "application/json"})
            with urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (URLError, HTTPError, json.JSONDecodeError) as e:
            return None

    def _extract_result(self, response):
        """Extract the 'result' field from a GhydraMCP HATEOAS response."""
        if response is None:
            return None
        if isinstance(response, dict):
            # GhydraMCP format: {"success": true, "result": ...}
            if "result" in response:
                return response["result"]
            # GhidraMCP format: direct result
            return response
        return response

    # ----------------------------------------------------------------
    # Connection & Discovery
    # ----------------------------------------------------------------

    def connect(self):
        """Auto-detect server type and verify connection."""
        # Try GhydraMCP first (has /api/instances)
        resp = self._get("/api/instances")
        if resp is not None:
            self.server_type = "ghydra"
            self.connected = True
            result = self._extract_result(resp)
            if isinstance(result, list) and result:
                self.program_name = result[0].get("program", None)
            return True

        # Try GhidraMCP / GhidrAssistMCP (simpler APIs)
        resp = self._get("/methods")
        if resp is not None:
            self.server_type = "ghidramcp"
            self.connected = True
            return True

        # Try GhidrAssistMCP
        resp = self._get("/")
        if resp is not None:
            self.server_type = "ghidrassist"
            self.connected = True
            return True

        return False

    def list_instances(self):
        """List active Ghidra instances (GhydraMCP only)."""
        resp = self._get("/api/instances")
        return self._extract_result(resp) or []

    def get_program_info(self):
        """Get info about the currently loaded program."""
        if self.server_type == "ghydra":
            resp = self._get("/api/project")
            return self._extract_result(resp)
        else:
            resp = self._get("/program/info")
            return resp

    # ----------------------------------------------------------------
    # Function Analysis
    # ----------------------------------------------------------------

    def list_functions(self, offset=0, limit=100, filter_name=None):
        """List functions in the binary."""
        if self.server_type == "ghydra":
            params = {"offset": offset, "limit": limit}
            resp = self._get("/api/functions", params)
            result = self._extract_result(resp)
        else:
            resp = self._get("/methods")
            result = resp

        if not result:
            return []

        funcs = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    f = FunctionInfo(
                        name=item.get("name", ""),
                        address=item.get("address", item.get("entryPoint", "")),
                        signature=item.get("signature", item.get("prototype", "")),
                        size=item.get("size", 0),
                        entry_point=item.get("entryPoint", item.get("address", "")),
                        is_thunk=item.get("isThunk", False),
                    )
                    if filter_name and filter_name.lower() not in (f.name or "").lower():
                        continue
                    funcs.append(f)
                elif isinstance(item, str):
                    # GhidraMCP returns list of strings
                    f = FunctionInfo(name=item)
                    if filter_name and filter_name.lower() not in item.lower():
                        continue
                    funcs.append(f)

        return funcs

    def get_function(self, name_or_addr):
        """Get detailed info about a single function."""
        if self.server_type == "ghydra":
            resp = self._get(f"/api/functions/{quote(str(name_or_addr))}")
            result = self._extract_result(resp)
            if result and isinstance(result, dict):
                return FunctionInfo(
                    name=result.get("name", ""),
                    address=result.get("address", result.get("entryPoint", "")),
                    signature=result.get("signature", result.get("prototype", "")),
                    size=result.get("size", 0),
                    entry_point=result.get("entryPoint", ""),
                    calling_convention=result.get("callingConvention", ""),
                    return_type=result.get("returnType", ""),
                    parameters=result.get("parameters", []),
                    is_thunk=result.get("isThunk", False),
                )
        return None

    def decompile(self, name_or_addr, style="default", syntax_tree=False):
        """Decompile a function to C pseudocode."""
        if self.server_type == "ghydra":
            params = {}
            if style != "default":
                params["style"] = style
            if syntax_tree:
                params["syntax_tree"] = "true"
            resp = self._get(f"/api/functions/{quote(str(name_or_addr))}/decompile", params)
            result = self._extract_result(resp)
            if isinstance(result, dict):
                return result.get("c_code", result.get("decompilation", str(result)))
            return result
        else:
            # GhidraMCP
            resp = self._get(f"/decompile/{quote(str(name_or_addr))}")
            if isinstance(resp, dict):
                return resp.get("decompilation", resp.get("c_code", str(resp)))
            return resp

    def disassemble(self, name_or_addr):
        """Get disassembly of a function."""
        if self.server_type == "ghydra":
            resp = self._get(f"/api/functions/{quote(str(name_or_addr))}/disassemble")
            return self._extract_result(resp)
        else:
            resp = self._get(f"/disassemble/{quote(str(name_or_addr))}")
            return resp

    def get_function_variables(self, name_or_addr):
        """Get function parameters and local variables."""
        if self.server_type == "ghydra":
            resp = self._get(f"/api/functions/{quote(str(name_or_addr))}/variables")
            result = self._extract_result(resp)
            if not result:
                return []
            variables = []
            if isinstance(result, list):
                for v in result:
                    variables.append(Variable(
                        name=v.get("name", ""),
                        data_type=v.get("dataType", v.get("type", "")),
                        storage=v.get("storage", ""),
                        size=v.get("size", 0),
                        is_parameter=v.get("isParameter", False),
                    ))
            return variables
        return []

    # ----------------------------------------------------------------
    # Analysis — Call Graph, Data Flow, XRefs
    # ----------------------------------------------------------------

    def get_callgraph(self, name_or_addr, max_depth=3):
        """Get call graph for a function."""
        if self.server_type == "ghydra":
            params = {"max_depth": max_depth}
            if name_or_addr.startswith("0x") or name_or_addr.startswith("0X"):
                params["address"] = name_or_addr
            else:
                params["name"] = name_or_addr
            resp = self._get("/api/analysis/callgraph", params)
            return self._extract_result(resp)
        return None

    def get_dataflow(self, address, direction="forward", max_steps=50):
        """Perform data flow analysis (GhydraMCP only)."""
        if self.server_type == "ghydra":
            params = {"address": address, "direction": direction, "max_steps": max_steps}
            resp = self._get("/api/analysis/dataflow", params)
            return self._extract_result(resp)
        return None

    def get_xrefs(self, to_addr=None, from_addr=None, ref_type=None, limit=100):
        """Get cross-references."""
        if self.server_type == "ghydra":
            params = {"limit": limit}
            if to_addr:
                params["to_addr"] = to_addr
            if from_addr:
                params["from_addr"] = from_addr
            if ref_type:
                params["type"] = ref_type
            resp = self._get("/api/xrefs", params)
            result = self._extract_result(resp)
            if not result:
                return []
            xrefs = []
            if isinstance(result, list):
                for x in result:
                    xrefs.append(XRef(
                        from_addr=x.get("fromAddress", ""),
                        to_addr=x.get("toAddress", ""),
                        ref_type=x.get("refType", x.get("type", "")),
                        from_func=x.get("fromFunction", ""),
                        to_func=x.get("toFunction", ""),
                    ))
            return xrefs
        return []

    # ----------------------------------------------------------------
    # Imports, Exports, Strings
    # ----------------------------------------------------------------

    def list_imports(self):
        """List imported functions."""
        if self.server_type == "ghydra":
            all_imports = []
            offset = 0
            while True:
                resp = self._get("/api/imports", {"offset": offset, "limit": 200})
                result = self._extract_result(resp)
                if not result or not isinstance(result, list):
                    break
                all_imports.extend(result)
                if len(result) < 200:
                    break
                offset += 200
            return all_imports
        else:
            resp = self._get("/imports")
            return resp if isinstance(resp, list) else []

    def list_exports(self):
        """List exported functions."""
        if self.server_type == "ghydra":
            all_exports = []
            offset = 0
            while True:
                resp = self._get("/api/exports", {"offset": offset, "limit": 200})
                result = self._extract_result(resp)
                if not result or not isinstance(result, list):
                    break
                all_exports.extend(result)
                if len(result) < 200:
                    break
                offset += 200
            return all_exports
        else:
            resp = self._get("/exports")
            return resp if isinstance(resp, list) else []

    def list_strings(self, filter_text=None, limit=200):
        """List defined strings in the binary."""
        if self.server_type == "ghydra":
            params = {"limit": limit}
            if filter_text:
                params["filter"] = filter_text
            resp = self._get("/api/data/strings", params)
            return self._extract_result(resp) or []
        return []

    # ----------------------------------------------------------------
    # Convenience — Fuzzing-Specific Queries
    # ----------------------------------------------------------------

    def find_file_io_callers(self):
        """
        Find all functions that call file I/O APIs (CreateFileW, fopen, etc.).
        Returns a list of (function_name, function_addr, api_called) tuples.
        """
        file_apis = [
            "CreateFileA", "CreateFileW", "CreateFile2",
            "fopen", "_wfopen", "_open",
            "ReadFile", "fread",
        ]

        callers = []
        imports = self.list_imports()
        if not imports:
            return callers

        for imp in imports:
            imp_name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
            if imp_name not in file_apis:
                continue

            imp_addr = imp.get("address", "") if isinstance(imp, dict) else ""
            if imp_addr:
                xrefs = self.get_xrefs(to_addr=imp_addr)
                for xref in xrefs:
                    callers.append({
                        "function": xref.from_func,
                        "address": xref.from_addr,
                        "api_called": imp_name,
                    })

        return callers

    def find_fuzz_candidates(self, max_depth=2):
        """
        Automated fuzzing target discovery using Ghidra analysis.
        Combines export analysis, file I/O xrefs, and call graph tracing.
        """
        candidates = []
        seen = set()

        # Strategy 1: Exported functions with parser-like names
        exports = self.list_exports()
        parser_kw = ["parse", "read", "load", "open", "decode", "process",
                      "import", "extract", "from_file", "fromfile", "from_stream",
                      "fromstream", "create_from", "createfrom", "init_from"]
        for exp in exports:
            name = exp.get("name", "") if isinstance(exp, dict) else str(exp)
            addr = exp.get("address", "") if isinstance(exp, dict) else ""
            name_lower = name.lower()
            for kw in parser_kw:
                if kw in name_lower:
                    if addr not in seen:
                        seen.add(addr)
                        candidates.append({
                            "name": name,
                            "address": addr,
                            "score": 30,
                            "reasons": [f"Export name contains '{kw}'"],
                            "source": "ghidra_export",
                        })
                    break

        # Strategy 2: Functions that call file I/O
        callers = self.find_file_io_callers()
        for c in callers:
            addr = c["address"]
            if addr not in seen:
                seen.add(addr)
                candidates.append({
                    "name": c["function"],
                    "address": addr,
                    "score": 40,
                    "reasons": [f"Calls {c['api_called']} (file I/O)"],
                    "source": "ghidra_xref",
                })
            else:
                # Boost score for already-seen
                for cand in candidates:
                    if cand["address"] == addr:
                        cand["score"] += 10
                        cand["reasons"].append(f"Also calls {c['api_called']}")
                        break

        # Strategy 3: Deep decompile top candidates to check for CloseHandle
        for cand in sorted(candidates, key=lambda x: x["score"], reverse=True)[:10]:
            name = cand["name"]
            if not name:
                continue
            code = self.decompile(name)
            if code:
                if "CloseHandle" in code or "fclose" in code:
                    cand["score"] += 20
                    cand["reasons"].append("Closes file handles (WinAFL compatible)")
                if "ExitProcess" in code or "TerminateProcess" in code:
                    cand["score"] -= 50
                    cand["reasons"].append("FATAL: Calls ExitProcess")
                if "malloc" in code or "HeapAlloc" in code:
                    cand["reasons"].append("Allocates memory")

        candidates.sort(key=lambda x: x["score"], reverse=True)
        return candidates

    def get_function_signature_c(self, name_or_addr):
        """
        Get the C function signature (return type + params) for harness typedef.
        Returns a string like 'int __stdcall FuncName(LPCWSTR param1, int param2)'.
        """
        func = self.get_function(name_or_addr)
        if func and func.signature:
            return func.signature

        # Fallback: try decompilation and extract first line
        code = self.decompile(name_or_addr)
        if code:
            for line in code.splitlines():
                line = line.strip()
                if line and not line.startswith("/*") and not line.startswith("//"):
                    if "(" in line and ")" in line:
                        return line.rstrip("{").strip()
                    break
        return None


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="ghidra_bridge",
        description="Ghidra Bridge — Test connection and query Ghidra MCP servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          %(prog)s --test localhost:8192
          %(prog)s --list-functions localhost:8192
          %(prog)s --list-functions localhost:8192 --filter CreateFile
          %(prog)s --decompile GdipLoadImageFromFile localhost:8192
          %(prog)s --callgraph main localhost:8192 --depth 3
          %(prog)s --xrefs-to 0x00401000 localhost:8192
          %(prog)s --find-fuzz-targets localhost:8192
          %(prog)s --signature GdipLoadImageFromFile localhost:8192
        """)
    )

    parser.add_argument("server", nargs="?", default="localhost:8192",
                        help="Ghidra server host:port (default: localhost:8192)")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--test", action="store_true", help="Test connection")
    group.add_argument("--list-functions", action="store_true", help="List functions")
    group.add_argument("--list-exports", action="store_true", help="List exports")
    group.add_argument("--list-imports", action="store_true", help="List imports")
    group.add_argument("--decompile", metavar="FUNC", help="Decompile a function")
    group.add_argument("--disassemble", metavar="FUNC", help="Disassemble a function")
    group.add_argument("--callgraph", metavar="FUNC", help="Get call graph")
    group.add_argument("--xrefs-to", metavar="ADDR", help="Get xrefs TO an address")
    group.add_argument("--xrefs-from", metavar="ADDR", help="Get xrefs FROM an address")
    group.add_argument("--find-fuzz-targets", action="store_true",
                        help="Auto-discover fuzzing targets")
    group.add_argument("--signature", metavar="FUNC", help="Get C function signature")
    group.add_argument("--variables", metavar="FUNC", help="Get function variables")

    parser.add_argument("--filter", help="Filter pattern for list operations")
    parser.add_argument("--depth", type=int, default=3, help="Call graph depth")
    parser.add_argument("--limit", type=int, default=50, help="Result limit")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    # Parse server address
    if ":" in args.server:
        host, port_str = args.server.rsplit(":", 1)
        port = int(port_str)
    else:
        host, port = args.server, 8192

    client = GhidraClient(host, port)

    # Test connection
    if args.test or not any([args.list_functions, args.list_exports, args.list_imports,
                              args.decompile, args.disassemble, args.callgraph,
                              args.xrefs_to, args.xrefs_from, args.find_fuzz_targets,
                              args.signature, args.variables]):
        print(f"\n  Ghidra Bridge — Connection Test")
        print(f"  Server: {host}:{port}\n")

        if client.connect():
            print(f"  [OK] Connected to {client.server_type} server")
            info = client.get_program_info()
            if info:
                print(f"  [OK] Program info: {json.dumps(info, indent=2)[:200]}")
            instances = client.list_instances()
            if instances:
                print(f"  [OK] Active instances: {len(instances)}")
            funcs = client.list_functions(limit=5)
            print(f"  [OK] Sample functions: {len(funcs)}")
            for f in funcs[:3]:
                print(f"       {f}")
        else:
            print(f"  [!!] Cannot connect to Ghidra at {host}:{port}")
            print(f"       Ensure Ghidra is running with a GhydraMCP/GhidraMCP plugin.")
            print(f"       Default ports: GhydraMCP=8192, GhidraMCP=8080")
        print()
        if args.test:
            return

    if not client.connected:
        if not client.connect():
            print(f"  [!!] Cannot connect to Ghidra at {host}:{port}")
            return

    # Commands
    if args.list_functions:
        funcs = client.list_functions(limit=args.limit, filter_name=args.filter)
        if args.json:
            print(json.dumps([f.to_dict() for f in funcs], indent=2))
        else:
            print(f"\n  Functions ({len(funcs)}):\n")
            for f in funcs:
                print(f"    {f.address or '?':>16s}  {f.name}")
            print()

    elif args.list_exports:
        exports = client.list_exports()
        if args.json:
            print(json.dumps(exports, indent=2))
        else:
            print(f"\n  Exports ({len(exports)}):\n")
            for exp in exports[:args.limit]:
                name = exp.get("name", "") if isinstance(exp, dict) else str(exp)
                addr = exp.get("address", "") if isinstance(exp, dict) else ""
                print(f"    {addr:>16s}  {name}")
            print()

    elif args.list_imports:
        imports = client.list_imports()
        if args.json:
            print(json.dumps(imports, indent=2))
        else:
            print(f"\n  Imports ({len(imports)}):\n")
            for imp in imports[:args.limit]:
                name = imp.get("name", "") if isinstance(imp, dict) else str(imp)
                print(f"    {name}")
            print()

    elif args.decompile:
        code = client.decompile(args.decompile)
        if code:
            if args.json:
                print(json.dumps({"function": args.decompile, "code": code}))
            else:
                print(f"\n  Decompilation: {args.decompile}\n")
                print(code)
        else:
            print(f"  [!!] Could not decompile '{args.decompile}'")

    elif args.disassemble:
        asm = client.disassemble(args.disassemble)
        if asm:
            if args.json:
                print(json.dumps({"function": args.disassemble, "disassembly": asm}))
            else:
                print(f"\n  Disassembly: {args.disassemble}\n")
                if isinstance(asm, list):
                    for line in asm:
                        print(f"    {line}")
                else:
                    print(asm)
        else:
            print(f"  [!!] Could not disassemble '{args.disassemble}'")

    elif args.callgraph:
        graph = client.get_callgraph(args.callgraph, max_depth=args.depth)
        if graph:
            if args.json:
                print(json.dumps(graph, indent=2))
            else:
                print(f"\n  Call Graph: {args.callgraph} (depth={args.depth})\n")
                print(json.dumps(graph, indent=2))
        else:
            print(f"  [!!] Could not get call graph for '{args.callgraph}'")

    elif args.xrefs_to:
        xrefs = client.get_xrefs(to_addr=args.xrefs_to, limit=args.limit)
        if args.json:
            print(json.dumps([x.to_dict() for x in xrefs], indent=2))
        else:
            print(f"\n  XRefs TO {args.xrefs_to} ({len(xrefs)}):\n")
            for x in xrefs:
                print(f"    {x.from_addr} ({x.from_func or '?'}) -> {x.to_addr} [{x.ref_type}]")
            print()

    elif args.xrefs_from:
        xrefs = client.get_xrefs(from_addr=args.xrefs_from, limit=args.limit)
        if args.json:
            print(json.dumps([x.to_dict() for x in xrefs], indent=2))
        else:
            print(f"\n  XRefs FROM {args.xrefs_from} ({len(xrefs)}):\n")
            for x in xrefs:
                print(f"    {x.from_addr} -> {x.to_addr} ({x.to_func or '?'}) [{x.ref_type}]")
            print()

    elif args.find_fuzz_targets:
        print(f"\n  Auto-discovering fuzzing targets via Ghidra analysis...\n")
        candidates = client.find_fuzz_candidates()
        if args.json:
            print(json.dumps(candidates, indent=2))
        else:
            for i, c in enumerate(candidates[:20]):
                print(f"  #{i+1:2d}  [Score: {c['score']:3d}]  {c['address']:>16s}  {c['name']}")
                for r in c["reasons"]:
                    print(f"       + {r}")
                print()

    elif args.signature:
        sig = client.get_function_signature_c(args.signature)
        if sig:
            print(f"\n  Signature: {sig}\n")
        else:
            print(f"  [!!] Could not get signature for '{args.signature}'")

    elif args.variables:
        variables = client.get_function_variables(args.variables)
        if args.json:
            print(json.dumps([v.to_dict() for v in variables], indent=2))
        else:
            print(f"\n  Variables for {args.variables} ({len(variables)}):\n")
            for v in variables:
                param_tag = " [PARAM]" if v.is_parameter else ""
                print(f"    {v.data_type or '?':>20s}  {v.name}{param_tag}")
            print()


if __name__ == "__main__":
    main()
