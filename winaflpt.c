/*
  WinAFL - Intel PT instrumentation and presistence via debugger code 
  ------------------------------------------------

  Written and maintained by Ivan Fratric <ifratric@google.com>

  Copyright 2016 Google Inc. All Rights Reserved.
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

#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdbool.h>
#include "windows.h"
#include "psapi.h"
#include "dbghelp.h"

#include "libipt.h"
#include "ipttool.h"

#include "intel-pt.h"

#include "types.h"
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"

#include "winaflpt.h"

#include "ptdecode.h"

// tests the custom decoders gainst the corresponding
// reference implementatopns from Intel
// used only for debugging
// #define DECODER_CORRECTNESS_TEST

u64 get_cur_time(void);
char *argv_to_cmd(char** argv);

#define CALLCONV_MICROSOFT_X64 0
#define CALLCONV_THISCALL 1
#define CALLCONV_FASTCALL 2
#define CALLCONV_CDECL 3
#define CALLCONV_DEFAULT 4

#define BREAKPOINT_UNKNOWN 0
#define BREAKPOINT_ENTRYPOINT 1
#define BREAKPOINT_MODULELOADED 2
#define BREAKPOINT_FUZZMETHOD 3

#define WINAFL_LOOP_EXCEPTION 0x0AF1

#define DEBUGGER_PROCESS_EXIT 0
#define DEBUGGER_FUZZMETHOD_REACHED 1
#define DEBUGGER_FUZZMETHOD_END 2
#define DEBUGGER_CRASHED 3
#define DEBUGGER_HANGED 4

#define DECODER_TIP_FAST 0
#define DECODER_TIP_REFERENCE 1
#define DECODER_FULL_FAST 2
#define DECODER_FULL_REFERENCE 3

static HANDLE child_handle, child_thread_handle;
static HANDLE devnul_handle = INVALID_HANDLE_VALUE;
static int fuzz_iterations_current;

static DWORD fuzz_thread_id;

static DEBUG_EVENT dbg_debug_event;
static DWORD dbg_continue_status;
static bool dbg_continue_needed;
static uint64_t dbg_timeout_time;

static bool child_entrypoint_reached;

static unsigned char *trace_buffer;
static size_t trace_size;

extern u8 *trace_bits;

extern HANDLE child_handle, child_thread_handle;
extern int fuzz_iterations_current;

extern HANDLE devnul_handle;
extern u8 sinkhole_stds;

extern u64 mem_limit;
extern u64 cpu_aff;

extern char *fuzzer_id;

static FILE *debug_log = NULL;

static struct pt_image_section_cache *section_cache;
static char section_cache_dir[MAX_PATH];

static int wow64_target = 0;
static size_t child_ptr_size = sizeof(void *);

address_range* coverage_ip_ranges = NULL;
size_t num_ip_ranges = 0;
static bool need_build_ranges = true;

static size_t last_ring_buffer_offset = 0;

#define USAGE_CHECK(condition, message) if(!(condition)) FATAL("%s\n", message);

enum {
	/* 00 */ FAULT_NONE,
	/* 01 */ FAULT_TMOUT,
	/* 02 */ FAULT_CRASH,
	/* 03 */ FAULT_ERROR,
	/* 04 */ FAULT_NOINST,
	/* 05 */ FAULT_NOBITS
};

typedef struct _module_info_t {
	char module_name[MAX_PATH];
	int isid;
	void *base;
	size_t size;
	struct _module_info_t *next;
} module_info_t;

static module_info_t *all_modules = NULL;

typedef struct _winafl_option_t {
	bool debug_mode;
	int coverage_kind;
	module_info_t *coverage_modules;
	char fuzz_module[MAX_PATH];
	char fuzz_method[MAX_PATH];
	unsigned long fuzz_offset;
	int fuzz_iterations;
	int num_fuz_args;
	int callconv;
	int decoder;
	bool thread_coverage;
	unsigned long trace_buffer_size;
	unsigned long trace_cache_size;
	bool persistent_trace;

	void **func_args;
	void *sp;
	void *fuzz_address;
} winafl_option_t;
static winafl_option_t options;

struct winafl_breakpoint {
	void *address;
	int type;
	unsigned char original_opcode;
	char module_name[MAX_PATH];
	void *module_base;
	struct winafl_breakpoint *next;
};
struct winafl_breakpoint *breakpoints;

static void
winaflpt_options_init(int argc, const char *argv[])
{
	int i;
	const char *token;
	module_info_t *coverage_modules;
	/* default values */
	options.debug_mode = false;
	options.coverage_kind = COVERAGE_BB;
	options.coverage_modules = NULL;
	options.fuzz_module[0] = 0;
	options.fuzz_method[0] = 0;
	options.fuzz_offset = 0;
	options.fuzz_iterations = 1000;
	options.func_args = NULL;
	options.num_fuz_args = 0;
	options.thread_coverage = true;
	options.callconv = CALLCONV_DEFAULT;
	options.decoder = DECODER_FULL_FAST;
	options.trace_buffer_size = TRACE_BUFFER_SIZE_DEFAULT;
	options.trace_cache_size = 0;
	options.persistent_trace = true;

	for (i = 0; i < argc; i++) {
		token = argv[i];
		if (strcmp(token, "-thread_coverage") == 0)
			options.thread_coverage = true;
		else if (strcmp(token, "-debug") == 0)
			options.debug_mode = true;
		else if (strcmp(token, "-nopersistent_trace") == 0)
			options.persistent_trace = false;
		else if (strcmp(token, "-covtype") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing coverage type");
			token = argv[++i];
			if (strcmp(token, "bb") == 0) options.coverage_kind = COVERAGE_BB;
			else if (strcmp(token, "edge") == 0) options.coverage_kind = COVERAGE_EDGE;
			else USAGE_CHECK(false, "invalid coverage type");
		}
		else if (strcmp(token, "-coverage_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			coverage_modules = options.coverage_modules;
			options.coverage_modules = (module_info_t *)malloc(sizeof(module_info_t));
			options.coverage_modules->next = coverage_modules;
			options.coverage_modules->isid = 0;
			options.coverage_modules->base = NULL;
			options.coverage_modules->size = 0;
			strncpy(options.coverage_modules->module_name, argv[++i], MAX_PATH);
		}
		else if (strcmp(token, "-target_module") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing module");
			strncpy(options.fuzz_module, argv[++i], MAX_PATH);
		}
		else if (strcmp(token, "-target_method") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing method");
			strncpy(options.fuzz_method, argv[++i], MAX_PATH);
		}
		else if (strcmp(token, "-fuzz_iterations") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of iterations");
			options.fuzz_iterations = atoi(argv[++i]);
		}
		else if (strcmp(token, "-nargs") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing number of arguments");
			options.num_fuz_args = atoi(argv[++i]);
		}
		else if (strcmp(token, "-target_offset") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing offset");
			options.fuzz_offset = strtoul(argv[++i], NULL, 0);
		}
		else if (strcmp(token, "-trace_size") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing trace size");
			options.trace_buffer_size = strtoul(argv[++i], NULL, 0);
		}
		else if (strcmp(token, "-trace_cache_size") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing trace cache size");
			options.trace_cache_size = strtoul(argv[++i], NULL, 0);
		}
		else if (strcmp(token, "-call_convention") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing calling convention");
			++i;
			if (strcmp(argv[i], "stdcall") == 0)
				options.callconv = CALLCONV_CDECL;
			else if (strcmp(argv[i], "fastcall") == 0)
				options.callconv = CALLCONV_FASTCALL;
			else if (strcmp(argv[i], "thiscall") == 0)
				options.callconv = CALLCONV_THISCALL;
			else if (strcmp(argv[i], "ms64") == 0)
				options.callconv = CALLCONV_MICROSOFT_X64;
			else
				FATAL("Unknown calling convention");
		} else if (strcmp(token, "-decoder") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing decoder");
			++i;
			if (strcmp(argv[i], "tip") == 0)
				options.decoder = DECODER_TIP_FAST;
			else if (strcmp(argv[i], "tip_ref") == 0)
				options.decoder = DECODER_TIP_REFERENCE;
			else if (strcmp(argv[i], "full") == 0)
				options.decoder = DECODER_FULL_FAST;
			else if (strcmp(argv[i], "full_ref") == 0)
				options.decoder = DECODER_FULL_REFERENCE;
			else
				FATAL("Unknown decoder value");
		} else {
			FATAL("UNRECOGNIZED OPTION: \"%s\"\n", token);
		}
	}

	if (options.fuzz_module[0] && (options.fuzz_offset == 0) && (options.fuzz_method[0] == 0)) {
		FATAL("If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well");
	}

	if (options.num_fuz_args) {
		options.func_args = (void **)malloc(options.num_fuz_args * sizeof(void *));
	}
}

int address_range_compare(const void * a, const void * b) {
	if (((address_range *)a)->start >= ((address_range *)b)->start) return 1;
	else return -1;
}

void build_address_ranges() {
	int num_loaded_modules;
	module_info_t *current_module;

	if (coverage_ip_ranges) free(coverage_ip_ranges);

	if (!options.coverage_modules) {
		num_ip_ranges = 1;
		coverage_ip_ranges = (address_range*)malloc(num_ip_ranges * sizeof(address_range));
		coverage_ip_ranges[0].start = 0;
		coverage_ip_ranges[0].end = 0xFFFFFFFFFFFFFFFFULL;
		coverage_ip_ranges[0].collect = 1;
		return;
	}
	
	// count loaded modules
	num_loaded_modules = 0;
	current_module = options.coverage_modules;
	while (current_module) {
		if (current_module->size > 0) {
			num_loaded_modules++;
		}
		current_module = current_module->next;
	}

	address_range* tmp_buf = (address_range*)malloc(num_loaded_modules * sizeof(address_range));

	num_loaded_modules = 0;
	current_module = options.coverage_modules;
	while (current_module) {
		if (current_module->size > 0) {
			tmp_buf[num_loaded_modules].start = (uint64_t)current_module->base;
			tmp_buf[num_loaded_modules].end = (uint64_t)current_module->base + current_module->size - 1;
			tmp_buf[num_loaded_modules].collect = 1;
			num_loaded_modules++;
		}
		current_module = current_module->next;
	}

	qsort(tmp_buf, num_loaded_modules, sizeof(address_range), address_range_compare);

	num_ip_ranges = num_loaded_modules * 2 + 1;
	coverage_ip_ranges = (address_range*)malloc(num_ip_ranges * sizeof(address_range));

	uint64_t current_address = 0;
	for (int i = 0; i < num_loaded_modules; i++) {
		coverage_ip_ranges[2 * i].start = current_address;
		coverage_ip_ranges[2 * i].end = tmp_buf[i].start - 1;
		coverage_ip_ranges[2 * i].collect = 0;
		coverage_ip_ranges[2 * i + 1] = tmp_buf[i];
		current_address = tmp_buf[i].end + 1;
	}
	coverage_ip_ranges[2 * num_loaded_modules].start = current_address;
	coverage_ip_ranges[2 * num_loaded_modules].end = 0xFFFFFFFFFFFFFFFFULL;
	coverage_ip_ranges[2 * num_loaded_modules].collect = 0;

	free(tmp_buf);
}

// appends new data to the trace_buffer
void append_trace_data(unsigned char *trace_data, size_t append_size) {
	size_t space_left = options.trace_buffer_size - trace_size;

	if (!space_left) {
		// stop collecting trace if the trace buffer is full;
		printf("Warning: Trace buffer is full\n");
		return;
	}

	if (append_size > space_left) {
		append_size = space_left;
	}

	if (append_size == 0) return;

	memcpy(trace_buffer + trace_size, trace_data, append_size);
	trace_size += append_size;
}


// returns true if the ring buffer was overflowed
bool collect_thread_trace(PIPT_TRACE_HEADER traceHeader) {
	// printf("ring offset: %u\n", traceHeader->RingBufferOffset);

	bool trace_buffer_overflow = false;

	unsigned char psb_and_psbend[] = {
		0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
		0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
		0x02, 0x23
	};

	trace_size = 0;

	if (options.persistent_trace) {

		// an ugly hack: trace might not start with a psb (synchronization) packet
		// so we are just adding one. This assumes the state has been properly
		// flushed when a breakpoint between two iterations has been hit
		// which does appear to be the case. However, if this doesn't occur
		// persistent tracing will not work properly
		append_trace_data(psb_and_psbend, sizeof(psb_and_psbend));

		// first, optimistically assume the buffer didn't overflow
		if (traceHeader->RingBufferOffset > last_ring_buffer_offset) {
			append_trace_data(traceHeader->Trace + last_ring_buffer_offset, traceHeader->RingBufferOffset - last_ring_buffer_offset);
		}
		else if (traceHeader->RingBufferOffset < last_ring_buffer_offset) {
			append_trace_data(traceHeader->Trace + last_ring_buffer_offset, traceHeader->TraceSize - last_ring_buffer_offset);
			append_trace_data(traceHeader->Trace, traceHeader->RingBufferOffset);
		}

		if (!check_trace_start(trace_buffer, trace_size, (uint64_t)options.fuzz_address)) {
			// most likely the ring buffer overflowd, extract what we can (trace tail)

			trace_size = 0;
			trace_buffer_overflow = true;

			printf("Warning: Trace buffer overflowed, trace will be truncated\n");
			if (options.debug_mode) fprintf(debug_log, "Trace buffer overflowed, trace will be truncated\n");

			char *trailing_data = traceHeader->Trace + traceHeader->RingBufferOffset;
			size_t trailing_size = traceHeader->TraceSize - traceHeader->RingBufferOffset;
			append_trace_data(trailing_data, trailing_size);

			append_trace_data(traceHeader->Trace, traceHeader->RingBufferOffset);

		}

		last_ring_buffer_offset = traceHeader->RingBufferOffset;

	} else {

		// check if the trace buffer overflowed

		char *trailing_data = traceHeader->Trace + traceHeader->RingBufferOffset;
		size_t trailing_size = traceHeader->TraceSize - traceHeader->RingBufferOffset;
		if (findpsb(&trailing_data, &trailing_size)) {
			trace_buffer_overflow = true;
			printf("Warning: Trace buffer overflowed, trace will be truncated\n");
			if (options.debug_mode) fprintf(debug_log, "Trace buffer overflowed, trace will be truncated\n");
			append_trace_data(trailing_data, trailing_size);
		}

		append_trace_data(traceHeader->Trace, traceHeader->RingBufferOffset);
	}

	return trace_buffer_overflow;
}

// parse PIPT_TRACE_DATA, extract trace bits and add them to the trace_buffer
// returns true if the trace ring buffer overflowed
bool collect_trace(PIPT_TRACE_DATA pTraceData)
{
	bool trace_buffer_overflow = false;

	PIPT_TRACE_HEADER traceHeader;
	DWORD dwTraceSize;

	dwTraceSize = pTraceData->TraceSize;

	traceHeader = (PIPT_TRACE_HEADER)pTraceData->TraceData;

	while (dwTraceSize > (unsigned)(FIELD_OFFSET(IPT_TRACE_HEADER, Trace))) {
		if (traceHeader->ThreadId == fuzz_thread_id) {
			trace_buffer_overflow = collect_thread_trace(traceHeader);
		}

		dwTraceSize -= (FIELD_OFFSET(IPT_TRACE_HEADER, Trace) + traceHeader->TraceSize);

		traceHeader = (PIPT_TRACE_HEADER)(traceHeader->Trace +
			traceHeader->TraceSize);
	}

	return trace_buffer_overflow;
}

// returns an array of handles for all modules loaded in the target process
DWORD get_all_modules(HMODULE **modules) {
	DWORD module_handle_storage_size = 1024 * sizeof(HMODULE);
	HMODULE *module_handles = (HMODULE *)malloc(module_handle_storage_size);
	DWORD hmodules_size;
	while (true) {
		if (!EnumProcessModulesEx(child_handle, module_handles, module_handle_storage_size, &hmodules_size, LIST_MODULES_ALL)) {
			FATAL("EnumProcessModules failed, %x\n", GetLastError());
		}
		if (hmodules_size <= module_handle_storage_size) break;
		module_handle_storage_size *= 2;
		module_handles = (HMODULE *)realloc(module_handles, module_handle_storage_size);
	}
	*modules = module_handles;
	return hmodules_size / sizeof(HMODULE);
}

// parses PE headers and gets the module entypoint
void *get_entrypoint(void *base_address) {
	unsigned char headers[4096];
	size_t num_read = 0;
	if (!ReadProcessMemory(child_handle, base_address, headers, 4096, &num_read) || (num_read != 4096)) {
		FATAL("Error reading target memory\n");
	}
	DWORD pe_offset;
	pe_offset = *((DWORD *)(headers + 0x3C));
	char *pe = headers + pe_offset;
	DWORD signature = *((DWORD *)pe);
	if (signature != 0x00004550) {
		FATAL("PE signature error\n");
	}
	pe = pe + 0x18;
	WORD magic = *((WORD *)pe);
	if ((magic != 0x10b) && (magic != 0x20b)) {
		FATAL("Unknown PE magic value\n");
	} 
	DWORD entrypoint_offset = *((DWORD *)(pe + 16));
	if (entrypoint_offset == 0) return NULL;
	return (char *)base_address + entrypoint_offset;
}

// adds a breakpoint at a specified address
// type, module_name and module_base are all additional information
// that can be accessed later when the breakpoint gets hit
void add_breakpoint(void *address, int type, char *module_name, void *module_base) {
	struct winafl_breakpoint *new_breakpoint = (struct winafl_breakpoint *)malloc(sizeof(struct winafl_breakpoint));
	size_t rwsize = 0;
	if(!ReadProcessMemory(child_handle, address, &(new_breakpoint->original_opcode), 1, &rwsize) || (rwsize != 1)) {
		FATAL("Error reading target memory\n");
	}
	rwsize = 0;	
	unsigned char cc = 0xCC;
	if (!WriteProcessMemory(child_handle, address, &cc, 1, &rwsize) || (rwsize != 1)) {
		FATAL("Error writing target memory\n");
	}
	FlushInstructionCache(child_handle, address, 1);
	new_breakpoint->address = address;
	new_breakpoint->type = type;
	if (module_name) {
		strcpy(new_breakpoint->module_name, module_name);
	} else {
		new_breakpoint->module_name[0] = 0;
	}
	new_breakpoint->module_base = module_base;
	new_breakpoint->next = breakpoints;
	breakpoints = new_breakpoint;
}


// damn it Windows, why don't you have a GetProcAddress
// that works on another process
DWORD get_proc_offset(char *data, char *name) {
	DWORD pe_offset;
	pe_offset = *((DWORD *)(data + 0x3C));
	char *pe = data + pe_offset;
	DWORD signature = *((DWORD *)pe);
	if (signature != 0x00004550) {
		return 0;
	}
	pe = pe + 0x18;
	WORD magic = *((WORD *)pe);
	DWORD exporttableoffset;
	if (magic == 0x10b) {
		exporttableoffset = *(DWORD *)(pe + 96);
	} else if (magic == 0x20b) {
		exporttableoffset = *(DWORD *)(pe + 112);
	} else {
		return 0;
	}

	if (!exporttableoffset) return 0;
	char *exporttable = data + exporttableoffset;

	DWORD numentries = *(DWORD *)(exporttable + 24);
	DWORD addresstableoffset = *(DWORD *)(exporttable + 28);
	DWORD nameptrtableoffset = *(DWORD *)(exporttable + 32);
	DWORD ordinaltableoffset = *(DWORD *)(exporttable + 36);
	DWORD *nameptrtable = (DWORD *)(data + nameptrtableoffset);
	WORD *ordinaltable = (WORD *)(data + ordinaltableoffset);
	DWORD *addresstable = (DWORD *)(data + addresstableoffset);

	DWORD i;
	for (i = 0; i < numentries; i++) {
		char *nameptr = data + nameptrtable[i];
		if (strcmp(name, nameptr) == 0) break;
	}

	if (i == numentries) return 0;

	WORD oridnal = ordinaltable[i];
	DWORD offset = addresstable[oridnal];

	return offset;
}

// attempt to obtain the fuzz_offset in various ways
char *get_fuzz_method_offset(HMODULE module) {
	MODULEINFO module_info;
	GetModuleInformation(child_handle, module, &module_info, sizeof(module_info));

	// if fuzz_offset is defined, use that
	if (options.fuzz_offset) {
		return (char *)module_info.lpBaseOfDll + options.fuzz_offset;
	}

	// try the exported symbols next
	BYTE *modulebuf = (BYTE *)malloc(module_info.SizeOfImage);
	size_t num_read;
	if (!ReadProcessMemory(child_handle, module_info.lpBaseOfDll, modulebuf, module_info.SizeOfImage, &num_read) || (num_read != module_info.SizeOfImage)) {
		FATAL("Error reading target memory\n");
	}
	DWORD fuzz_offset = get_proc_offset(modulebuf, options.fuzz_method);
	free(modulebuf);
	if (fuzz_offset) {
		return (char *)module + fuzz_offset;
	}

	// finally, try the debug symbols
	char *fuzz_method = NULL;
	char base_name[MAX_PATH];
	GetModuleBaseNameA(child_handle, module, (LPSTR)(&base_name), sizeof(base_name));

	char module_path[MAX_PATH];
	if(!GetModuleFileNameExA(child_handle, module, module_path, sizeof(module_path))) return NULL;
	
	ULONG64 buffer[(sizeof(SYMBOL_INFO) +
		MAX_SYM_NAME * sizeof(TCHAR) +
		sizeof(ULONG64) - 1) /
		sizeof(ULONG64)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	SymInitialize(child_handle, NULL, false);
	DWORD64 sym_base_address = SymLoadModuleEx(child_handle, NULL, module_path, NULL, 0, 0, NULL, 0);
	if (SymFromName(child_handle, options.fuzz_method, pSymbol)) {
		options.fuzz_offset = (unsigned long)(pSymbol->Address - sym_base_address);
		fuzz_method = (char *)module_info.lpBaseOfDll + options.fuzz_offset;
	}
	SymCleanup(child_handle);

	return fuzz_method;
}

// should we collect coverage for this module
module_info_t *is_coverage_module(char *module_name) {
	module_info_t *current_module = options.coverage_modules;
	while (current_module) {
		if (_stricmp(module_name, current_module->module_name) == 0) {
			return current_module;
		}
		current_module = current_module->next;
	}
	return NULL;
}

// check if the same module was already loaded
module_info_t *get_loaded_module(char *module_name, void *base) {
	module_info_t *current_module = all_modules;
	while (current_module) {
		if (_stricmp(module_name, current_module->module_name) == 0) {
			if (base == NULL || base == current_module->base) {
				return current_module;
			}
		}
		current_module = current_module->next;
	}
	return NULL;
}

// find if there is a *different* module that previously occupied
// the same space
module_info_t *get_intersecting_module(char *module_name, void *base, DWORD size) {
	module_info_t *current_module = all_modules;
	while (current_module) {
		if (((uint64_t)current_module->base + current_module->size <= (uint64_t)base) || 
			((uint64_t)base + size <= (uint64_t)current_module->base)) {
			current_module = current_module->next;
			continue;
		}
		return current_module;
	}
	return NULL;
}


void on_coverage_module_loaded(HMODULE module, module_info_t *target_module) {
	MODULEINFO module_info;
	GetModuleInformation(child_handle, module, &module_info, sizeof(module_info));

	target_module->base = module_info.lpBaseOfDll;
	target_module->size = module_info.SizeOfImage;

	need_build_ranges = true;
}

size_t ReadProcessMemory_tolerant(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
	LPCVOID end_address = (char *)lpBaseAddress + nSize;
	LPCVOID cur_address = lpBaseAddress;
	MEMORY_BASIC_INFORMATION meminfobuf;
	size_t size_read;
	size_t total_size_read = 0;

	while (cur_address < end_address) {
		size_t ret = VirtualQueryEx(hProcess, (LPCVOID)cur_address, &meminfobuf, sizeof(MEMORY_BASIC_INFORMATION));
		if (!ret) break;

		size_t offset = (size_t)meminfobuf.BaseAddress - (size_t)lpBaseAddress;
		size_t to_read = meminfobuf.RegionSize;
		if ((offset + to_read) > nSize) {
			to_read = nSize - offset;
		}

		if (ReadProcessMemory(child_handle, meminfobuf.BaseAddress, (char *)lpBuffer + offset, to_read, &size_read)) {
			total_size_read += size_read;
		}

		cur_address = (char *)meminfobuf.BaseAddress + meminfobuf.RegionSize;
	}

	return total_size_read;
}

void add_module_to_section_cache(HMODULE module, char *module_name) {
	module_info_t *loaded_module;
	MODULEINFO module_info;
	GetModuleInformation(child_handle, module, &module_info, sizeof(module_info));

	// handle the case where module was loaded previously
	loaded_module = get_loaded_module(module_name, module_info.lpBaseOfDll);
	if (loaded_module) {
		// same module loaded on the same address, skip
		return;
	}

	// this will *probably* never happen but check for it anyway
	loaded_module = get_intersecting_module(module_name, module_info.lpBaseOfDll, module_info.SizeOfImage);
	if (loaded_module) {
		FATAL("Module %s loaded in the address range that module %s previously occupied. This is currently unsupported.",
			module_name, loaded_module->module_name);
	}

	loaded_module = (module_info_t *)malloc(sizeof(module_info_t));
	strcpy(loaded_module->module_name, module_name);
	loaded_module->base = module_info.lpBaseOfDll;
	loaded_module->size = module_info.SizeOfImage;

	// todo put these files in a separate directory and clean it periodically
	char tmpfilename[MAX_PATH];
	sprintf(tmpfilename, "%s\\sectioncache_%p.dat", section_cache_dir, module_info.lpBaseOfDll);

	BYTE *modulebuf = (BYTE *)malloc(module_info.SizeOfImage);
	size_t num_read;
	if (!ReadProcessMemory(child_handle, module_info.lpBaseOfDll, modulebuf, module_info.SizeOfImage, &num_read) || (num_read != module_info.SizeOfImage)) {
		if (!ReadProcessMemory_tolerant(child_handle, module_info.lpBaseOfDll, modulebuf, module_info.SizeOfImage)) {
			FATAL("Error reading memory for module %s", module_name);
		}
	}

	// this is pretty horrible, writing a file only to be read again
	// but libipt only supports reading sections from file, not memory
	FILE *fp = fopen(tmpfilename, "wb");
	if (!fp) {
		FATAL("Error opening image cache file.");
	}
	fwrite(modulebuf, 1, module_info.SizeOfImage, fp);
	fclose(fp);

	loaded_module->isid = pt_iscache_add_file(section_cache, tmpfilename, 0, module_info.SizeOfImage, (uint64_t)module_info.lpBaseOfDll);

	free(modulebuf);

	if (loaded_module->isid <= 0) {
		FATAL("Error adding file to pt cache.");
	}

	loaded_module->next = all_modules;
	all_modules = loaded_module;
}

// called when a potentialy interesting module gets loaded
void on_module_loaded(HMODULE module, char *module_name) {
	MODULEINFO module_info;
	GetModuleInformation(child_handle, module, &module_info, sizeof(module_info));
	// printf("In on_module_loaded, name: %s, base: %p\n", module_name, module_info.lpBaseOfDll);

	module_info_t *coverage_module = is_coverage_module(module_name);
	if (coverage_module) {
		on_coverage_module_loaded(module, coverage_module);
	}

	if (options.decoder == DECODER_FULL_FAST || options.decoder == DECODER_FULL_REFERENCE) {
		add_module_to_section_cache(module, module_name);
	}

	if (_stricmp(module_name, options.fuzz_module) == 0) {
		char * fuzz_address = get_fuzz_method_offset(module);
		if (!fuzz_address) {
			FATAL("Error determining target method address\n");
		}

		// printf("Fuzz method address: %p\n", fuzz_address);
		options.fuzz_address = fuzz_address;

		add_breakpoint(fuzz_address, BREAKPOINT_FUZZMETHOD, NULL, 0);
	}
}

void read_stack(void *stack_addr, void **buffer, size_t numitems) {
	size_t numrw = 0;
#ifdef _WIN64
	if (wow64_target) {
		uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
		ReadProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
		for (size_t i = 0; i < numitems; i++) {
			buffer[i] = (void *)((size_t)buf32[i]);
		}
		free(buf32);
		return;
	}
#endif
	ReadProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

void write_stack(void *stack_addr, void **buffer, size_t numitems) {
	size_t numrw = 0;
#ifdef _WIN64
	if (wow64_target) {
		uint32_t *buf32 = (uint32_t *)malloc(numitems * child_ptr_size);
		for (size_t i = 0; i < numitems; i++) {
			buf32[i] = (uint32_t)((size_t)buffer[i]);
		}
		WriteProcessMemory(child_handle, stack_addr, buf32, numitems * child_ptr_size, &numrw);
		free(buf32);
		return;
	}
#endif
	WriteProcessMemory(child_handle, stack_addr, buffer, numitems * child_ptr_size, &numrw);
}

// called when the target method is called *for the first time only*
void on_target_method(DWORD thread_id) {
	// printf("in OnTargetMethod\n");

	fuzz_thread_id = thread_id;

	size_t numrw = 0;

	CONTEXT lcContext;
	lcContext.ContextFlags = CONTEXT_ALL;
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	GetThreadContext(thread_handle, &lcContext);

	// read out and save the params
#ifdef _WIN64
	options.sp = (void *)lcContext.Rsp;
#else
	options.sp = (void *)lcContext.Esp;
#endif

	switch (options.callconv) {
#ifdef _WIN64
	case CALLCONV_DEFAULT:
	case CALLCONV_MICROSOFT_X64:
		if (options.num_fuz_args > 0) options.func_args[0] = (void *)lcContext.Rcx;
		if (options.num_fuz_args > 1) options.func_args[1] = (void *)lcContext.Rdx;
		if (options.num_fuz_args > 2) options.func_args[2] = (void *)lcContext.R8;
		if (options.num_fuz_args > 3) options.func_args[3] = (void *)lcContext.R9;
		if (options.num_fuz_args > 4) {
			read_stack((void *)(lcContext.Rsp + 5 * child_ptr_size), options.func_args + 4, options.num_fuz_args - 4);
		}
		break;
	case CALLCONV_CDECL:
		if (options.num_fuz_args > 0) {
			read_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args, options.num_fuz_args);
		}
		break;
	case CALLCONV_FASTCALL:
		if (options.num_fuz_args > 0) options.func_args[0] = (void *)lcContext.Rcx;
		if (options.num_fuz_args > 1) options.func_args[1] = (void *)lcContext.Rdx;
		if (options.num_fuz_args > 3) {
			read_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args + 2, options.num_fuz_args - 2);
		}
		break;
	case CALLCONV_THISCALL:
		if (options.num_fuz_args > 0) options.func_args[0] = (void *)lcContext.Rcx;
		if (options.num_fuz_args > 3) {
			read_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args + 1, options.num_fuz_args - 1);
		}
		break;
#else
	case CALLCONV_MICROSOFT_X64:
		FATAL("X64 callong convention not supported for 32-bit targets");
		break;
	case CALLCONV_DEFAULT:
	case CALLCONV_CDECL:
		if (options.num_fuz_args > 0) {
			read_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args, options.num_fuz_args);
		}
		break;
	case CALLCONV_FASTCALL:
		if (options.num_fuz_args > 0) options.func_args[0] = (void *)lcContext.Ecx;
		if (options.num_fuz_args > 1) options.func_args[1] = (void *)lcContext.Edx;
		if (options.num_fuz_args > 3) {
			read_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args + 2, options.num_fuz_args - 2);
		}
		break;
	case CALLCONV_THISCALL:
		if (options.num_fuz_args > 0) options.func_args[0] = (void *)lcContext.Ecx;
		if (options.num_fuz_args > 3) {
			read_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args + 1, options.num_fuz_args - 1);
		}
		break;
#endif
	default:
		break;
	}

	// todo store any target-specific additional context here

	// modify the return address on the stack so that an exception is triggered
	// when the target function finishes executing
	// another option would be to allocate a block of executable memory
	// and point return address over there, but this is quicker
	size_t return_address = WINAFL_LOOP_EXCEPTION;
	WriteProcessMemory(child_handle, options.sp, &return_address, child_ptr_size, &numrw);

	CloseHandle(thread_handle);
}

// called every time the target method returns
void on_target_method_ended(DWORD thread_id) {
	// printf("in OnTargetMethodEnded\n");

	CONTEXT lcContext;
	lcContext.ContextFlags = CONTEXT_ALL;
	HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	GetThreadContext(thread_handle, &lcContext);

	// restore params
#ifdef _WIN64
	lcContext.Rip = (size_t)options.fuzz_address;
	lcContext.Rsp = (size_t)options.sp;
#else
	lcContext.Eip = (size_t)options.fuzz_address;
	lcContext.Esp = (size_t)options.sp;
#endif

	switch (options.callconv) {
#ifdef _WIN64
	case CALLCONV_DEFAULT:
	case CALLCONV_MICROSOFT_X64:
		if (options.num_fuz_args > 0) lcContext.Rcx = (size_t)options.func_args[0];
		if (options.num_fuz_args > 1) lcContext.Rdx = (size_t)options.func_args[1];
		if (options.num_fuz_args > 2) lcContext.R8 = (size_t)options.func_args[2];
		if (options.num_fuz_args > 3) lcContext.R9 = (size_t)options.func_args[3];
		if (options.num_fuz_args > 4) {
			write_stack((void *)(lcContext.Rsp + 5 * child_ptr_size), options.func_args + 4, options.num_fuz_args - 4);
		}
		break;
	case CALLCONV_CDECL:
		if (options.num_fuz_args > 0) {
			write_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args, options.num_fuz_args);
	}
		break;
	case CALLCONV_FASTCALL:
		if (options.num_fuz_args > 0) lcContext.Rcx = (size_t)options.func_args[0];
		if (options.num_fuz_args > 1) lcContext.Rdx = (size_t)options.func_args[1];
		if (options.num_fuz_args > 3) {
			write_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args + 2, options.num_fuz_args - 2);
		}
		break;
	case CALLCONV_THISCALL:
		if (options.num_fuz_args > 0) lcContext.Rcx = (size_t)options.func_args[0];
		if (options.num_fuz_args > 3) {
			write_stack((void *)(lcContext.Rsp + child_ptr_size), options.func_args + 1, options.num_fuz_args - 1);
		}
		break;
#else
	case CALLCONV_MICROSOFT_X64:
		FATAL("X64 callong convention not supported for 32-bit targets");
		break;
	case CALLCONV_DEFAULT:
	case CALLCONV_CDECL:
		if (options.num_fuz_args > 0) {
			write_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args, options.num_fuz_args);
		}
		break;
	case CALLCONV_FASTCALL:
		if (options.num_fuz_args > 0) lcContext.Ecx = (size_t)options.func_args[0];
		if (options.num_fuz_args > 1) lcContext.Edx = (size_t)options.func_args[1];
		if (options.num_fuz_args > 3) {
			write_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args + 2, options.num_fuz_args - 2);
		}
		break;
	case CALLCONV_THISCALL:
		if (options.num_fuz_args > 0) lcContext.Ecx = (size_t)options.func_args[0];
		if (options.num_fuz_args > 3) {
			write_stack((void *)(lcContext.Esp + child_ptr_size), options.func_args + 1, options.num_fuz_args - 1);
		}
		break;
#endif
	default:
		break;
	}

	// todo restore any target-specific additional context here

	SetThreadContext(thread_handle, &lcContext);
	CloseHandle(thread_handle);
}

// called when process entrypoint gets reached
void on_entrypoint() {
	// printf("Entrypoint\n");

	HMODULE *module_handles = NULL;
	DWORD num_modules = get_all_modules(&module_handles);
	for (DWORD i = 0; i < num_modules; i++) {
		char base_name[MAX_PATH];
		GetModuleBaseNameA(child_handle, module_handles[i], (LPSTR)(&base_name), sizeof(base_name));
		if(options.debug_mode) fprintf(debug_log, "Module loaded: %s\n", base_name);
		on_module_loaded(module_handles[i], base_name);
	}
	if(module_handles) free(module_handles);

	child_entrypoint_reached = true;
}

// called when the debugger hits a breakpoint
int handle_breakpoint(void *address, DWORD thread_id) {
	int ret = BREAKPOINT_UNKNOWN;
	size_t rwsize = 0;
	struct winafl_breakpoint *previous = NULL;
	struct winafl_breakpoint *current = breakpoints;
	while (current) {
		if (current->address == address) {
			// unlink the breakpoint
			if (previous) previous->next = current->next;
			else breakpoints = current->next;
			// restore address
			if (!WriteProcessMemory(child_handle, address, &current->original_opcode, 1, &rwsize) || (rwsize != 1)) {
				FATAL("Error writing child memory\n");
			}
			FlushInstructionCache(child_handle, address, 1);
			// restore context
			CONTEXT lcContext;
			lcContext.ContextFlags = CONTEXT_ALL;
			HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
			GetThreadContext(thread_handle, &lcContext);
#ifdef _WIN64
			lcContext.Rip--;
#else
			lcContext.Eip--;
#endif
			SetThreadContext(thread_handle, &lcContext);
			CloseHandle(thread_handle);
			// handle breakpoint
			switch (current->type) {
			case BREAKPOINT_ENTRYPOINT:
				on_entrypoint();
				break;
			case BREAKPOINT_MODULELOADED:
				on_module_loaded((HMODULE)current->module_base, current->module_name);
				break;
			case BREAKPOINT_FUZZMETHOD:
				on_target_method(thread_id);
				break;
			default:
				break;
			}
			// return the brekpoint type
			ret = current->type;
			// delete the breakpoint object
			free(current);
			//done
			break;
		}
		previous = current;
		current = current->next;
	}
	return ret;
}

// standard debugger loop that listens to relevant events in the target process
int debug_loop()
{
	bool alive = true;

	LPDEBUG_EVENT DebugEv = &dbg_debug_event;

	while(alive)
	{

		BOOL wait_ret = WaitForDebugEvent(DebugEv, 100);

		// printf("time: %lld\n", get_cur_time_us());

		if (wait_ret) {
			dbg_continue_needed = true;
		} else {
			dbg_continue_needed = false;
		}

		if (get_cur_time() > dbg_timeout_time) return DEBUGGER_HANGED;

		if (!wait_ret) {
			//printf("WaitForDebugEvent returned 0\n");
			continue;
		}

		dbg_continue_status = DBG_CONTINUE;

		// printf("eventCode: %x\n", DebugEv->dwDebugEventCode);

		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			// printf("exception code: %x\n", DebugEv->u.Exception.ExceptionRecord.ExceptionCode);

			switch (DebugEv->u.Exception.ExceptionRecord.ExceptionCode)
			{
			case EXCEPTION_BREAKPOINT:
			case 0x4000001f: //STATUS_WX86_BREAKPOINT
			{
				void *address = DebugEv->u.Exception.ExceptionRecord.ExceptionAddress;
				// printf("Breakpoint at address %p\n", address);
				int breakpoint_type = handle_breakpoint(address, DebugEv->dwThreadId);
				if (breakpoint_type == BREAKPOINT_UNKNOWN) {
					dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
				} else if (breakpoint_type == BREAKPOINT_FUZZMETHOD) {
					dbg_continue_status = DBG_CONTINUE;
					return DEBUGGER_FUZZMETHOD_REACHED;
				} else {
					dbg_continue_status = DBG_CONTINUE;
				}
				break;
			}

			case EXCEPTION_ACCESS_VIOLATION: {
				if ((size_t)DebugEv->u.Exception.ExceptionRecord.ExceptionAddress == WINAFL_LOOP_EXCEPTION) {
					on_target_method_ended(DebugEv->dwThreadId);
					dbg_continue_status = DBG_CONTINUE;
					return DEBUGGER_FUZZMETHOD_END;
				} else {
					dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
					return DEBUGGER_CRASHED;
				}
				break;
			}

			case EXCEPTION_ILLEGAL_INSTRUCTION:
			case EXCEPTION_PRIV_INSTRUCTION:
			case EXCEPTION_INT_DIVIDE_BY_ZERO:
			case EXCEPTION_STACK_OVERFLOW:
			case STATUS_HEAP_CORRUPTION:
			case STATUS_STACK_BUFFER_OVERRUN:
			case STATUS_FATAL_APP_EXIT:
				dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
				return DEBUGGER_CRASHED;
				break;

			default:
				dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}

			break;

		case CREATE_THREAD_DEBUG_EVENT:
			break;

		case CREATE_PROCESS_DEBUG_EVENT: {
			// add a brekpoint to the process entrypoint
			void *entrypoint = get_entrypoint(DebugEv->u.CreateProcessInfo.lpBaseOfImage);
			add_breakpoint(entrypoint, BREAKPOINT_ENTRYPOINT, NULL, 0);
			CloseHandle(DebugEv->u.CreateProcessInfo.hFile);
			break;
		}

		case EXIT_THREAD_DEBUG_EVENT:
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			alive = false;
			break;

		case LOAD_DLL_DEBUG_EVENT: {
			// Don't do anything until the processentrypoint is reached.
			// Before that time we can't do much anyway, a lot of calls are going to fail
			// Modules loaded before entrypoint is reached are going to be enumerated at that time
			if (child_entrypoint_reached) {
				char filename[MAX_PATH];
				GetFinalPathNameByHandleA(DebugEv->u.LoadDll.hFile, (LPSTR)(&filename), sizeof(filename), 0);
				char *base_name = strrchr(filename, '\\');
				if (base_name) base_name += 1;
				else base_name = filename;
				// printf("Module loaded: %s %p\n", base_name, DebugEv->u.LoadDll.lpBaseOfDll);
				if (options.debug_mode) fprintf(debug_log, "Module loaded: %s\n", base_name);
				// module isn't fully loaded yet. Instead of processing it now,
				// add a breakpoint to the module's entrypoint
				if ((_stricmp(base_name, options.fuzz_module) == 0) || 
					is_coverage_module(base_name) ||
					options.decoder == DECODER_FULL_REFERENCE ||
					options.decoder == DECODER_FULL_FAST)
				{
					void *entrypoint = get_entrypoint(DebugEv->u.LoadDll.lpBaseOfDll);
					// printf("module %s entrypoint %p\n", base_name, entrypoint);
					// if there is no entrypoint assume resource-only dll
					if (entrypoint) {
						add_breakpoint(entrypoint, BREAKPOINT_MODULELOADED,
							base_name, DebugEv->u.LoadDll.lpBaseOfDll);
					} else {
						printf("Warning: module %s has no entrypoint, "
							"assuming resource-only. "
							"If you believe this is not the case, "
							"please file a bug\n", base_name);
					}
				}
			}
			CloseHandle(DebugEv->u.LoadDll.hFile);
			break;
		}

		case UNLOAD_DLL_DEBUG_EVENT:
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			break;

		case RIP_EVENT:
			break;
		}

		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dbg_continue_status);
	}

	return DEBUGGER_PROCESS_EXIT;
}

// a simpler debugger loop that just waits for the process to exit
void wait_process_exit()
{
	bool alive = true;

	LPDEBUG_EVENT DebugEv = &dbg_debug_event;

	while (alive)
	{
		dbg_continue_status = DBG_CONTINUE;

		if (!WaitForDebugEvent(DebugEv, 100)) {
			continue;
		}

		//printf("eventCode: %x\n", DebugEv->dwDebugEventCode);

		switch (DebugEv->dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			dbg_continue_status = DBG_EXCEPTION_NOT_HANDLED;
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			CloseHandle(DebugEv->u.CreateProcessInfo.hFile);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			alive = false;
			break;

		case LOAD_DLL_DEBUG_EVENT:
			CloseHandle(DebugEv->u.LoadDll.hFile);
			break;

		default:
			break;
		}

		ContinueDebugEvent(DebugEv->dwProcessId,
			DebugEv->dwThreadId,
			dbg_continue_status);
	}
}

// starts the target process
void start_process(char *cmd) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	HANDLE hJob = NULL;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limit;

	breakpoints = NULL;

	if (sinkhole_stds && devnul_handle == INVALID_HANDLE_VALUE) {
		devnul_handle = CreateFile(
			"nul",
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);

		if (devnul_handle == INVALID_HANDLE_VALUE) {
			PFATAL("Unable to open the nul device.");
		}
	}
	BOOL inherit_handles = TRUE;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// todo the below is duplicating code from afl-fuzz.c a lot
	// this should be taken out to a separate function
	if (sinkhole_stds) {
		si.hStdOutput = si.hStdError = devnul_handle;
		si.dwFlags |= STARTF_USESTDHANDLES;
	}
	else {
		inherit_handles = FALSE;
	}

	if (mem_limit || cpu_aff) {
		hJob = CreateJobObject(NULL, NULL);
		if (hJob == NULL) {
			FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
		}

		ZeroMemory(&job_limit, sizeof(job_limit));
		if (mem_limit) {
			job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
			job_limit.ProcessMemoryLimit = (size_t)(mem_limit * 1024 * 1024);
		}

		if (cpu_aff) {
			job_limit.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
			job_limit.BasicLimitInformation.Affinity = (DWORD_PTR)cpu_aff;
		}

		if (!SetInformationJobObject(
			hJob,
			JobObjectExtendedLimitInformation,
			&job_limit,
			sizeof(job_limit)
		)) {
			FATAL("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
		}
	}

	if (!CreateProcessA(NULL, cmd, NULL, NULL, inherit_handles, DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
		FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
	}

	child_handle = pi.hProcess;
	child_thread_handle = pi.hThread;
	child_entrypoint_reached = false;

	if (mem_limit || cpu_aff) {
		if (!AssignProcessToJobObject(hJob, child_handle)) {
			FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
		}
	}

	BOOL wow64current, wow64remote;
	if (!IsWow64Process(child_handle, &wow64remote)) {
		FATAL("IsWow64Process failed");
	}
	if (wow64remote) {
		wow64_target = 1;
		child_ptr_size = 4;
		if (options.callconv == CALLCONV_DEFAULT) {
			options.callconv = CALLCONV_CDECL;
		}
	}
	if (!IsWow64Process(GetCurrentProcess(), &wow64current)) {
		FATAL("IsWow64Process failed");
	}
	if (wow64current && wow64remote && (options.decoder == DECODER_FULL_REFERENCE || options.decoder == DECODER_FULL_FAST)) {
		FATAL("For full Intel PT decoding on 64-bit windows, you must use a 64-bit WinAFL build even on 32-bit targets");
	}
}

// called to resume the target process if it is waiting on a debug event
void resumes_process() {
	ContinueDebugEvent(dbg_debug_event.dwProcessId,
		dbg_debug_event.dwThreadId,
		dbg_continue_status);
}

void kill_process() {
	// end tracing
	if (options.persistent_trace) {
		if (!StopProcessIptTracing(child_handle)) {
			printf("Error stopping ipt trace\n");
		}
	}

	TerminateProcess(child_handle, 0);

	if(dbg_continue_needed) resumes_process();

	wait_process_exit();

	CloseHandle(child_handle);
	CloseHandle(child_thread_handle);

	child_handle = NULL;
	child_thread_handle = NULL;

	// delete any breakpoints that weren't hit
	struct winafl_breakpoint *breakpoint = breakpoints;
	while (breakpoint) {
		struct winafl_breakpoint *tmp = breakpoint;
		breakpoint = breakpoint->next;
		free(tmp);
	}
	breakpoints = NULL;
}

int run_target_pt(char **argv, uint32_t timeout) {
	int debugger_status;
	int ret;

	if (!child_handle) {

		char *cmd = argv_to_cmd(argv);
		start_process(cmd);
		ck_free(cmd);

		// wait until the target method is reached
		dbg_timeout_time = get_cur_time() + timeout;
		debugger_status = debug_loop();

		if (debugger_status != DEBUGGER_FUZZMETHOD_REACHED) {
			switch (debugger_status) {
			case DEBUGGER_CRASHED:
				FATAL("Process crashed before reaching the target method\n");
				break;
			case DEBUGGER_HANGED:
				FATAL("Process hanged before reaching the target method\n");
				break;
			case DEBUGGER_PROCESS_EXIT:
				FATAL("Process exited before reaching the target method\n");
				break;
			default:
				FATAL("An unknown problem occured before reaching the target method\n");
				break;
			}
		}

		fuzz_iterations_current = 0;
	}

	if(options.debug_mode) fprintf(debug_log, "iteration %d\n", fuzz_iterations_current);

	// start tracing
	if ((!options.persistent_trace) || (fuzz_iterations_current == 0)) {
		IPT_OPTIONS ipt_options;
		memset(&ipt_options, 0, sizeof(IPT_OPTIONS));
		ipt_options.OptionVersion = 1;
		ConfigureBufferSize(options.trace_buffer_size, &ipt_options);
		ConfigureTraceFlags(0, &ipt_options);
		if (!StartProcessIptTracing(child_handle, ipt_options)) {
			FATAL("ipt tracing error\n");
		}
		last_ring_buffer_offset = 0;
	}

	memset(trace_bits, 0, MAP_SIZE);

	dbg_timeout_time = get_cur_time() + timeout;

	// printf("iteration start\n");

	resumes_process();
	debugger_status = debug_loop();

	// printf("iteration end\n");

	// collect trace
	bool trace_buffer_overflowed = false;
	PIPT_TRACE_DATA trace_data = GetIptTrace(child_handle);
	if (!trace_data) {
		printf("Error getting ipt trace\n");
	} else {
		trace_buffer_overflowed = collect_trace(trace_data);
		HeapFree(GetProcessHeap(), 0, trace_data);
	}

	// end tracing
	if (!options.persistent_trace) {
		if (!StopProcessIptTracing(child_handle)) {
			printf("Error stopping ipt trace\n");
		}
	}

	if (need_build_ranges) {
		build_address_ranges();
		need_build_ranges = false;
	}

	// process trace

	// printf("decoding trace of %llu bytes\n", trace_size);

	struct pt_image *image = NULL;
	if ((options.decoder == DECODER_FULL_FAST) || (options.decoder == DECODER_FULL_REFERENCE)) {
		image = pt_image_alloc("winafl_image");
		module_info_t *cur_module = all_modules;
		while (cur_module) {
			if (cur_module->isid > 0) {
				int ret = pt_image_add_cached(image, section_cache, cur_module->isid, NULL);
			}
			cur_module = cur_module->next;
		}
	}

	if (options.decoder == DECODER_TIP_FAST) {
		decode_trace_tip_fast(trace_buffer, trace_size, options.coverage_kind);
#ifdef DECODER_CORRECTNESS_TEST
		printf("Testing decoder correctness\n");
		unsigned char *fast_trace_bits = (unsigned char *)malloc(MAP_SIZE);
		memcpy(fast_trace_bits, trace_bits, MAP_SIZE);
		memset(trace_bits, 0, MAP_SIZE);
		decode_trace_tip_reference(trace_buffer, trace_size, options.coverage_kind);
		if (memcmp(fast_trace_bits, trace_bits, MAP_SIZE)) {
			FATAL("Fast decoder returned different coverage than the reference decoder");
		}
		free(fast_trace_bits);
#endif
	} else if (options.decoder == DECODER_TIP_REFERENCE) {
		decode_trace_tip_reference(trace_buffer, trace_size, options.coverage_kind);
	} else if (options.decoder == DECODER_FULL_FAST) {
		analyze_trace_full_fast(trace_buffer, trace_size, options.coverage_kind, image, trace_buffer_overflowed);
#ifdef DECODER_CORRECTNESS_TEST
		printf("Testing decoder correctness\n");
		unsigned char *fast_trace_bits = (unsigned char *)malloc(MAP_SIZE);
		memcpy(fast_trace_bits, trace_bits, MAP_SIZE);
		memset(trace_bits, 0, MAP_SIZE);
		analyze_trace_full_reference(trace_buffer, trace_size, options.coverage_kind, image, trace_buffer_overflowed);
		if (memcmp(fast_trace_bits, trace_bits, MAP_SIZE)) {
			FATAL("Fast decoder returned different coverage than the reference decoder");
		}
		free(fast_trace_bits);
#endif
	} else if (options.decoder == DECODER_FULL_REFERENCE) {
		analyze_trace_full_reference(trace_buffer, trace_size, options.coverage_kind, image, trace_buffer_overflowed);
	}

	if(image) pt_image_free(image);

	if (debugger_status == DEBUGGER_PROCESS_EXIT) {
		CloseHandle(child_handle);
		CloseHandle(child_thread_handle);
		child_handle = NULL;
		child_thread_handle = NULL;
		ret = FAULT_TMOUT; //treat it as a hang
	} else if (debugger_status == DEBUGGER_HANGED) {
		kill_process();
		ret = FAULT_TMOUT;
	} else if (debugger_status == DEBUGGER_CRASHED) {
		kill_process();
		ret = FAULT_CRASH;
	} else if (debugger_status == DEBUGGER_FUZZMETHOD_END) {
		ret = FAULT_NONE;
	}

	fuzz_iterations_current++;
	if (fuzz_iterations_current == options.fuzz_iterations && child_handle != NULL) {
		kill_process();
	}

	return ret;
}

int pt_init(int argc, char **argv, char *module_dir) {
	child_handle = NULL;
	child_thread_handle = NULL;

	int lastoption = -1;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			lastoption = i;
			break;
		}
	}

	if (lastoption <= 0) return 0;

	winaflpt_options_init(lastoption - 1, argv + 1);
	trace_buffer = (unsigned char *)malloc(options.trace_buffer_size);

	if (!EnableAndValidateIptServices()) {
		FATAL("No IPT\n");
	} else {
		printf("IPT service enebled\n");
	}

	if (options.debug_mode) {
		debug_log = fopen("debug.log", "w");
		if (!debug_log) {
			FATAL("Can't open debug log for writing");
		}
	}

	if (options.decoder == DECODER_FULL_FAST || options.decoder == DECODER_FULL_REFERENCE) {
		section_cache = pt_iscache_alloc("winafl_cache");
	}
	strcpy(section_cache_dir, module_dir);

	if (options.decoder == DECODER_FULL_FAST) {
		if (!options.trace_cache_size) {
			// simple heuristics for determining tracelet cache size
			// within reasonable bounds
			options.trace_cache_size = options.trace_buffer_size * 10;
			if (options.trace_cache_size < TRACE_CACHE_SIZE_MIN)
				options.trace_cache_size = TRACE_CACHE_SIZE_MIN;
			if (options.trace_cache_size > TRACE_CACHE_SIZE_MAX)
				options.trace_cache_size = TRACE_CACHE_SIZE_MAX;

		}
		tracelet_cache_init(options.trace_cache_size / 100, options.trace_cache_size);
	}

	return lastoption;
}

void debug_target_pt(char **argv) {
	trace_bits = (u8 *)malloc(MAP_SIZE);
	u8 * trace_bits_saved = (u8 *)malloc(MAP_SIZE);

	for (int i = 0; i < options.fuzz_iterations; i++) {
		int ret = run_target_pt(argv, 0xFFFFFFFF);

		// detect variable coverage, could indicate a decoding issue
		// skip 1st iteration, will likely hit more coverage
		if (i == 1) {
			memcpy(trace_bits_saved, trace_bits, MAP_SIZE);
		} else if(i > 1) {
			if (memcmp(trace_bits_saved, trace_bits, MAP_SIZE)) {
				// printf("Info: Variable coverage detected\n");
			}
		}

		switch (ret) {
		case FAULT_NONE:
			if(debug_log) fprintf(debug_log, "Iteration finished normally\n");
			break;
		case FAULT_CRASH:
			if (debug_log) fprintf(debug_log, "Target crashed\n");
			break;
		case FAULT_TMOUT:
			if (debug_log) fprintf(debug_log, "Target hanged\n");
			break;
		}
	}

	if (debug_log) {
		fprintf(debug_log, "Coverage map (hex): \n");
		size_t map_pos = 0;
		while (1) {
			for (int i = 0; i < 16; i++) {
				if (map_pos == MAP_SIZE) break;
				fprintf(debug_log, "%02X", trace_bits[map_pos]);
				map_pos++;
			}
			fprintf(debug_log, "\n");
			if (map_pos == MAP_SIZE) break;
		}
	}

	if (debug_log) fclose(debug_log);
}
