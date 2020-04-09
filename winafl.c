/*
   WinAFL - DynamoRIO client (instrumentation) code
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

#define _CRT_SECURE_NO_WARNINGS

#define MAP_SIZE 65536

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drreg.h"
#include "drwrap.h"

#ifdef USE_DRSYMS
#include "drsyms.h"
#endif

#include "modules.h"
#include "utils.h"
#include "hashtable.h"
#include "drtable.h"
#include "limits.h"
#include <string.h>
#include <stdlib.h>
#include <windows.h>

#define UNKNOWN_MODULE_ID USHRT_MAX

#ifndef PF_FASTFAIL_AVAILABLE
#define PF_FASTFAIL_AVAILABLE 23
#endif

#ifndef STATUS_FATAL_APP_EXIT
#define STATUS_FATAL_APP_EXIT ((DWORD)0x40000015L)
#endif

#ifndef STATUS_HEAP_CORRUPTION
#define STATUS_HEAP_CORRUPTION 0xC0000374
#endif

static uint verbose;

#define NOTIFY(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, __VA_ARGS__); \
} while (0)

#define OPTION_MAX_LENGTH MAXIMUM_PATH

#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

//fuzz modes
enum persistence_mode_t { native_mode = 0,	in_app = 1,};

typedef struct _target_module_t {
    char module_name[MAXIMUM_PATH];
    struct _target_module_t *next;
} target_module_t;

typedef struct _winafl_option_t {
    /* Use nudge to notify the process for termination so that
     * event_exit will be called.
     */
    bool nudge_kills;
    bool debug_mode;
	  int persistence_mode;
    int coverage_kind;
    char logdir[MAXIMUM_PATH];
    target_module_t *target_modules;
    char fuzz_module[MAXIMUM_PATH];
    char fuzz_method[MAXIMUM_PATH];
    char pipe_name[MAXIMUM_PATH];
    char shm_name[MAXIMUM_PATH];
    unsigned long fuzz_offset;
    int fuzz_iterations;
    void **func_args;
    int num_fuz_args;
    drwrap_callconv_t callconv;
    bool thread_coverage;
    bool no_loop;
	bool dr_persist_cache;
} winafl_option_t;
static winafl_option_t options;

#define NUM_THREAD_MODULE_CACHE 4

typedef struct _winafl_data_t {
    module_entry_t *cache[NUM_THREAD_MODULE_CACHE];
    file_t  log;
    unsigned char *fake_afl_area; //used for thread_coverage
    unsigned char *afl_area;
} winafl_data_t;
static winafl_data_t winafl_data;

static int winafl_tls_field;

typedef struct _fuzz_target_t {
    reg_t xsp;            /* stack level at entry to the fuzz target */
    app_pc func_pc;
    int iteration;
} fuzz_target_t;
static fuzz_target_t fuzz_target;

typedef struct _debug_data_t {
    int pre_hanlder_called;
    int post_handler_called;
} debug_data_t;
static debug_data_t debug_data;

static module_table_t *module_table;
static client_id_t client_id;

static volatile bool go_native;

static void
event_exit(void);

static void
event_thread_exit(void *drcontext);

static HANDLE pipe;

/****************************************************************************
 * Nudges
 */

enum {
    NUDGE_TERMINATE_PROCESS = 1,
};

static void
event_nudge(void *drcontext, uint64 argument)
{
    int nudge_arg = (int)argument;
    int exit_arg  = (int)(argument >> 32);
    if (nudge_arg == NUDGE_TERMINATE_PROCESS) {
        static int nudge_term_count;
        /* handle multiple from both NtTerminateProcess and NtTerminateJobObject */
        uint count = dr_atomic_add32_return_sum(&nudge_term_count, 1);
        if (count == 1) {
            dr_exit_process(exit_arg);
        }
    }
    ASSERT(nudge_arg == NUDGE_TERMINATE_PROCESS, "unsupported nudge");
    ASSERT(false, "should not reach"); /* should not reach */
}

static bool
event_soft_kill(process_id_t pid, int exit_code)
{
    /* we pass [exit_code, NUDGE_TERMINATE_PROCESS] to target process */
    dr_config_status_t res;
    res = dr_nudge_client_ex(pid, client_id,
                             NUDGE_TERMINATE_PROCESS | (uint64)exit_code << 32,
                             0);
    if (res == DR_SUCCESS) {
        /* skip syscall since target will terminate itself */
        return true;
    }
    /* else failed b/c target not under DR control or maybe some other
     * error: let syscall go through
     */
    return false;
}

/****************************************************************************
 * Event Callbacks
 */

char ReadCommandFromPipe()
{
	DWORD num_read;
	char result;
	ReadFile(pipe, &result, 1, &num_read, NULL);
	return result;
}

void WriteCommandToPipe(char cmd)
{
	DWORD num_written;
	WriteFile(pipe, &cmd, 1, &num_written, NULL);
}

void WriteDWORDCommandToPipe(DWORD data)
{
	DWORD num_written;
	WriteFile(pipe, &data, sizeof(DWORD), &num_written, NULL);
}


static void
dump_winafl_data()
{
    dr_write_file(winafl_data.log, winafl_data.afl_area, MAP_SIZE);
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    DWORD exception_code = excpt->record->ExceptionCode;

    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "Exception caught: %x\n", exception_code);

    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
       (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) ||
       (exception_code == STATUS_HEAP_CORRUPTION) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT)) {
            if(options.debug_mode) {
                dr_fprintf(winafl_data.log, "crashed\n");
            } else {
				WriteCommandToPipe('C');
				WriteDWORDCommandToPipe(exception_code);				
            }
            dr_exit_process(1);
    }
    return true;
}

static void event_thread_init(void *drcontext)
{
  void **thread_data;

  thread_data = (void **)dr_thread_alloc(drcontext, 2 * sizeof(void *));
  thread_data[0] = 0;
  if(options.thread_coverage) {
    thread_data[1] = winafl_data.fake_afl_area;
  } else {
    thread_data[1] = winafl_data.afl_area;
  }
  drmgr_set_tls_field(drcontext, winafl_tls_field, thread_data);
}

static void event_thread_exit(void *drcontext)
{
  void *data = drmgr_get_tls_field(drcontext, winafl_tls_field);
  dr_thread_free(drcontext, data, 2 * sizeof(void *));
}

static dr_emit_flags_t
instrument_bb_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    static bool debug_information_output = false;
    app_pc start_pc;
    module_entry_t **mod_entry_cache;
    module_entry_t *mod_entry;
    const char *module_name;
    uint offset;
    target_module_t *target_modules;
    bool should_instrument;
    unsigned char *afl_map;
	dr_emit_flags_t ret;

    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    start_pc = dr_fragment_app_pc(tag);

    mod_entry_cache = winafl_data.cache;
    mod_entry = module_table_lookup(mod_entry_cache,
                                                NUM_THREAD_MODULE_CACHE,
                                                module_table, start_pc);

    if (mod_entry == NULL || mod_entry->data == NULL) return DR_EMIT_DEFAULT;

    module_name = dr_module_preferred_name(mod_entry->data);

    should_instrument = false;
    target_modules = options.target_modules;
    while(target_modules) {
        if(_stricmp(module_name, target_modules->module_name) == 0) {
            should_instrument = true;
            if(options.debug_mode && debug_information_output == false) {
                dr_fprintf(winafl_data.log, "Instrumenting %s with the 'bb' mode\n", module_name);
                debug_information_output = true;
            }
            break;
        }
        target_modules = target_modules->next;
    }
    if(!should_instrument) return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;

    offset = (uint)(start_pc - mod_entry->data->start);
    offset &= MAP_SIZE - 1;

    afl_map = winafl_data.afl_area;

    drreg_reserve_aflags(drcontext, bb, inst);

    if(options.thread_coverage || options.dr_persist_cache) {
      reg_id_t reg;
      opnd_t opnd1, opnd2;
      instr_t *new_instr;

      drreg_reserve_register(drcontext, bb, inst, NULL, &reg);

      drmgr_insert_read_tls_field(drcontext, winafl_tls_field, bb, inst, reg);

      opnd1 = opnd_create_reg(reg);
      opnd2 = OPND_CREATE_MEMPTR(reg, sizeof(void *));
      new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
      instrlist_meta_preinsert(bb, inst, new_instr);

      opnd1 = OPND_CREATE_MEM8(reg, offset);
      new_instr = INSTR_CREATE_inc(drcontext, opnd1);
      instrlist_meta_preinsert(bb, inst, new_instr);

      drreg_unreserve_register(drcontext, bb, inst, reg);

	  ret = DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;

	} else {

      instrlist_meta_preinsert(bb, inst,
          INSTR_CREATE_inc(drcontext, OPND_CREATE_ABSMEM
          (&(afl_map[offset]), OPSZ_1)));

	  ret = DR_EMIT_DEFAULT;
    }

    drreg_unreserve_aflags(drcontext, bb, inst);

    return ret;
}

static dr_emit_flags_t
instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    static bool debug_information_output = false;
    app_pc start_pc;
    module_entry_t **mod_entry_cache;
    module_entry_t *mod_entry;
    reg_id_t reg, reg2, reg3;
    opnd_t opnd1, opnd2;
    instr_t *new_instr;
    const char *module_name;
    uint offset;
    target_module_t *target_modules;
    bool should_instrument;
	dr_emit_flags_t ret;

    if (!drmgr_is_first_instr(drcontext, inst))
        return DR_EMIT_DEFAULT;

    start_pc = dr_fragment_app_pc(tag);

    mod_entry_cache = winafl_data.cache;
    mod_entry = module_table_lookup(mod_entry_cache,
                                                NUM_THREAD_MODULE_CACHE,
                                                module_table, start_pc);

     if (mod_entry == NULL || mod_entry->data == NULL) return DR_EMIT_DEFAULT;

    module_name = dr_module_preferred_name(mod_entry->data);

    should_instrument = false;
    target_modules = options.target_modules;
    while(target_modules) {
        if(_stricmp(module_name, target_modules->module_name) == 0) {
            should_instrument = true;
            if(options.debug_mode && debug_information_output == false) {
                dr_fprintf(winafl_data.log, "Instrumenting %s with the 'edge' mode\n", module_name);
                debug_information_output = true;
            }
            break;
        }
        target_modules = target_modules->next;
    }
    if(!should_instrument) return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;

    offset = (uint)(start_pc - mod_entry->data->start);
    offset &= MAP_SIZE - 1;

    drreg_reserve_aflags(drcontext, bb, inst);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg3);

    //reg2 stores AFL area, reg 3 stores previous offset

    //load the pointer to previous offset in reg3
    drmgr_insert_read_tls_field(drcontext, winafl_tls_field, bb, inst, reg3);

    //load address of shm into reg2
    if(options.thread_coverage || options.dr_persist_cache) {
      opnd1 = opnd_create_reg(reg2);
      opnd2 = OPND_CREATE_MEMPTR(reg3, sizeof(void *));
      new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
      instrlist_meta_preinsert(bb, inst, new_instr);

	  ret = DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;

	} else {
      opnd1 = opnd_create_reg(reg2);
      opnd2 = OPND_CREATE_INTPTR((uint64)winafl_data.afl_area);
      new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
      instrlist_meta_preinsert(bb, inst, new_instr);

	  ret = DR_EMIT_DEFAULT;
    }

    //load previous offset into register
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_MEMPTR(reg3, 0);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //xor register with the new offset
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //increase the counter at reg + reg2
    opnd1 = opnd_create_base_disp(reg2, reg, 1, 0, OPSZ_1);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //store the new value
    offset = (offset >> 1)&(MAP_SIZE - 1);
    opnd1 = OPND_CREATE_MEMPTR(reg3, 0);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    drreg_unreserve_register(drcontext, bb, inst, reg3);
    drreg_unreserve_register(drcontext, bb, inst, reg2);
    drreg_unreserve_register(drcontext, bb, inst, reg);
    drreg_unreserve_aflags(drcontext, bb, inst);

    return ret;
}

static void
pre_loop_start_handler(void *wrapcxt, INOUT void **user_data)
{
	void *drcontext = drwrap_get_drcontext(wrapcxt);

	if (!options.debug_mode) {
		//let server know we finished a cycle, redundunt on first cycle.
		WriteCommandToPipe('K');

		if (fuzz_target.iteration == options.fuzz_iterations) {
			dr_exit_process(0);
		}
		fuzz_target.iteration++;

		//let server know we are starting a new cycle
		WriteCommandToPipe('P'); 

		//wait for server acknowledgement for cycle start
		char command = ReadCommandFromPipe(); 

		if (command != 'F') {
			if (command == 'Q') {
				dr_exit_process(0);
			}
			else {
				char errorMessage[] = "unrecognized command received over pipe: ";
				errorMessage[sizeof(errorMessage)-2] = command;
				DR_ASSERT_MSG(false, errorMessage);
			}
		}
	}
	else {
		debug_data.pre_hanlder_called++;
		dr_fprintf(winafl_data.log, "In pre_loop_start_handler: %d\n", debug_data.pre_hanlder_called);
	}

	memset(winafl_data.afl_area, 0, MAP_SIZE);

	if (options.coverage_kind == COVERAGE_EDGE || options.thread_coverage) {
		void **thread_data = (void **)drmgr_get_tls_field(drcontext, winafl_tls_field);
		thread_data[0] = 0;
		thread_data[1] = winafl_data.afl_area;
	}
}

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
    char command = 0;
    int i;
    void *drcontext;

    app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
    dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL);
    drcontext = drwrap_get_drcontext(wrapcxt);

    fuzz_target.xsp = mc->xsp;
    fuzz_target.func_pc = target_to_fuzz;

    if(!options.debug_mode) {
		WriteCommandToPipe('P');
		command = ReadCommandFromPipe();

        if(command != 'F') {
            if(command == 'Q') {
                dr_exit_process(0);
            } else {
                DR_ASSERT_MSG(false, "unrecognized command received over pipe");
            }
        }
    } else {
        debug_data.pre_hanlder_called++;
        dr_fprintf(winafl_data.log, "In pre_fuzz_handler\n");
    }

    //save or restore arguments
    if (!options.no_loop) {
        if (fuzz_target.iteration == 0) {
            for (i = 0; i < options.num_fuz_args; i++)
                options.func_args[i] = drwrap_get_arg(wrapcxt, i);
        } else {
            for (i = 0; i < options.num_fuz_args; i++)
                drwrap_set_arg(wrapcxt, i, options.func_args[i]);
        }
    }

    memset(winafl_data.afl_area, 0, MAP_SIZE);

    if(options.coverage_kind == COVERAGE_EDGE || options.thread_coverage) {
        void **thread_data = (void **)drmgr_get_tls_field(drcontext, winafl_tls_field);
        thread_data[0] = 0;
        thread_data[1] = winafl_data.afl_area;
    }
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
{
    dr_mcontext_t *mc;
    mc = drwrap_get_mcontext(wrapcxt);

    if(!options.debug_mode) {
		WriteCommandToPipe('K');
    } else {
        debug_data.post_handler_called++;
        dr_fprintf(winafl_data.log, "In post_fuzz_handler\n");
    }

    /* We don't need to reload context in case of network-based fuzzing. */
    if (options.no_loop)
        return;

    fuzz_target.iteration++;
    if(fuzz_target.iteration == options.fuzz_iterations) {
        dr_exit_process(0);
    }

    mc->xsp = fuzz_target.xsp;
    mc->pc = fuzz_target.func_pc;
	drwrap_redirect_execution(wrapcxt);
}

static void
createfilew_interceptor(void *wrapcxt, INOUT void **user_data)
{
    wchar_t *filenamew = (wchar_t *)drwrap_get_arg(wrapcxt, 0);
    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "In OpenFileW, reading %ls\n", filenamew);
}

static void
createfilea_interceptor(void *wrapcxt, INOUT void **user_data)
{
    char *filename = (char *)drwrap_get_arg(wrapcxt, 0);
    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "In OpenFileA, reading %s\n", filename);
}

static void
verfierstopmessage_interceptor_pre(void *wrapctx, INOUT void **user_data)
{
    EXCEPTION_RECORD exception_record = { 0 };
    dr_exception_t dr_exception = { 0 };
    dr_exception.record = &exception_record;
    exception_record.ExceptionCode = STATUS_HEAP_CORRUPTION;

    onexception(NULL, &dr_exception);
}

static void
recvfrom_interceptor(void *wrapcxt, INOUT void **user_data)
{
    if (options.debug_mode)
        dr_fprintf(winafl_data.log, "In recvfrom\n");
}

static void
recv_interceptor(void *wrapcxt, INOUT void **user_data)
{
    if (options.debug_mode)
        dr_fprintf(winafl_data.log, "In recv\n");
}

static void
isprocessorfeaturepresent_interceptor_pre(void *wrapcxt, INOUT void **user_data)
{
    DWORD feature = (DWORD)drwrap_get_arg(wrapcxt, 0);
    *user_data = (void*)feature;
}

static void
isprocessorfeaturepresent_interceptor_post(void *wrapcxt, void *user_data)
{
    DWORD feature = (DWORD)user_data;
    if(feature == PF_FASTFAIL_AVAILABLE) {
        if(options.debug_mode) {
            dr_fprintf(winafl_data.log, "About to make IsProcessorFeaturePresent(%d) returns 0\n", feature);
        }

        // Make the software thinks that _fastfail() is not supported.
        drwrap_set_retval(wrapcxt, (void*)0);
    }
}

static void
unhandledexceptionfilter_interceptor_pre(void *wrapcxt, INOUT void **user_data)
{
    PEXCEPTION_POINTERS exception = (PEXCEPTION_POINTERS)drwrap_get_arg(wrapcxt, 0);
    dr_exception_t dr_exception = { 0 };

    // Fake an exception
    dr_exception.record = exception->ExceptionRecord;
    onexception(NULL, &dr_exception);
}

static void
event_module_unload(void *drcontext, const module_data_t *info)
{
    module_table_unload(module_table, info);
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    const char *module_name = info->names.exe_name;
    app_pc to_wrap = 0;

    if (module_name == NULL) {
        // In case exe_name is not defined, we will fall back on the preferred name.
        module_name = dr_module_preferred_name(info);
    }

    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "Module loaded, %s\n", module_name);

    if(options.fuzz_module[0]) {
        if(_stricmp(module_name, options.fuzz_module) == 0) {
            if(options.fuzz_offset) {
                to_wrap = info->start + options.fuzz_offset;
            } else {
                //first try exported symbols
                to_wrap = (app_pc)dr_get_proc_address(info->handle, options.fuzz_method);
                if(!to_wrap) {
                    //if that fails, try with the symbol access library
#ifdef USE_DRSYMS
                    drsym_init(0);
                    drsym_lookup_symbol(info->full_path, options.fuzz_method, (size_t *)(&to_wrap), 0);
                    drsym_exit();
#endif
                    DR_ASSERT_MSG(to_wrap, "Can't find specified method in fuzz_module");                
                    to_wrap += (size_t)info->start;
                }
            }
			if (options.persistence_mode == native_mode)
			{
				drwrap_wrap_ex(to_wrap, pre_fuzz_handler, post_fuzz_handler, NULL, options.callconv);
			}
			if (options.persistence_mode == in_app)
			{
				drwrap_wrap_ex(to_wrap, pre_loop_start_handler, NULL, NULL, options.callconv);
			}
        }

        if (options.debug_mode && (_stricmp(module_name, "WS2_32.dll") == 0)) {
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "recvfrom");
            bool result = drwrap_wrap(to_wrap, recvfrom_interceptor, NULL);
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "recv");
            result = drwrap_wrap(to_wrap, recv_interceptor, NULL);
        }

        if(options.debug_mode && (_stricmp(module_name, "KERNEL32.dll") == 0)) {
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileW");
            drwrap_wrap(to_wrap, createfilew_interceptor, NULL);
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileA");
            drwrap_wrap(to_wrap, createfilea_interceptor, NULL);
        }

        if(_stricmp(module_name, "kernelbase.dll") == 0) {
            // Since Win8, software can use _fastfail() to trigger an exception that cannot be caught.
            // This is a problem for winafl as it also means DR won't be able to see it. Good thing is that
            // usually those routines (__report_gsfailure for example) accounts for platforms that don't
            // have support for fastfail. In those cases, they craft an exception record and pass it
            // to UnhandledExceptionFilter.
            //
            // To work around this we set up two hooks:
            //   (1) IsProcessorFeaturePresent(PF_FASTFAIL_AVAILABLE): to lie and pretend that the
            //       platform doesn't support fastfail.
            //   (2) UnhandledExceptionFilter: to intercept the exception record and forward it
            //       to winafl's exception handler.
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "IsProcessorFeaturePresent");
            drwrap_wrap(to_wrap, isprocessorfeaturepresent_interceptor_pre, isprocessorfeaturepresent_interceptor_post);
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "UnhandledExceptionFilter");
            drwrap_wrap(to_wrap, unhandledexceptionfilter_interceptor_pre, NULL);
        }
    }

    if (_stricmp(module_name, "verifier.dll") == 0) {
        to_wrap = (app_pc)dr_get_proc_address(info->handle, "VerifierStopMessage");
        drwrap_wrap(to_wrap, verfierstopmessage_interceptor_pre, NULL);
    }

    module_table_load(module_table, info);
}

static void
event_exit(void)
{
    if(options.debug_mode) {
        if(debug_data.pre_hanlder_called == 0) {
            dr_fprintf(winafl_data.log, "WARNING: Target function was never called. Incorrect target_offset?\n");
        } else if(debug_data.post_handler_called == 0 && options.persistence_mode != in_app) {
            dr_fprintf(winafl_data.log, "WARNING: Post-fuzz handler was never reached. Did the target function return normally?\n");
        } else if(debug_data.pre_hanlder_called == 1 && options.persistence_mode == in_app) {
            dr_fprintf(winafl_data.log, "WARNING: Only hit pre_loop_start_handler once, Is your target function in a loop?\n");
        } else {
            dr_fprintf(winafl_data.log, "Everything appears to be running normally.\n");
        }

        dr_fprintf(winafl_data.log, "Coverage map follows:\n");
        dump_winafl_data();
        dr_close_file(winafl_data.log);
    }

    /* destroy module table */
    module_table_destroy(module_table);

    drx_exit();
    drmgr_exit();
}

static void
event_init(void)
{
    char buf[MAXIMUM_PATH];

    module_table = module_table_create();

    memset(winafl_data.cache, 0, sizeof(winafl_data.cache));
    memset(winafl_data.afl_area, 0, MAP_SIZE);

    if(options.debug_mode) {
        debug_data.pre_hanlder_called = 0;
        debug_data.post_handler_called = 0;

        winafl_data.log =
            drx_open_unique_appid_file(options.logdir, dr_get_process_id(),
                                   "afl", "proc.log",
                                   DR_FILE_ALLOW_LARGE,
                                   buf, BUFFER_SIZE_ELEMENTS(buf));
        if (winafl_data.log != INVALID_FILE) {
            dr_log(NULL, LOG_ALL, 1, "winafl: log file is %s\n", buf);
            NOTIFY(1, "<created log file %s>\n", buf);
        }
    }

    fuzz_target.iteration = 0;
}


static void
setup_pipe() {
    pipe = CreateFile(
         options.pipe_name,   // pipe name
         GENERIC_READ |  // read and write access
         GENERIC_WRITE,
         0,              // no sharing
         NULL,           // default security attributes
         OPEN_EXISTING,  // opens existing pipe
         0,              // default attributes
         NULL);          // no template file

    if (pipe == INVALID_HANDLE_VALUE) DR_ASSERT_MSG(false, "error connecting to pipe");
}

static void
setup_shmem() {
   HANDLE map_file;

   map_file = OpenFileMapping(
                   FILE_MAP_ALL_ACCESS,   // read/write access
                   FALSE,                 // do not inherit the name
                   options.shm_name);            // name of mapping object

   if (map_file == NULL) DR_ASSERT_MSG(false, "error accesing shared memory");

   winafl_data.afl_area = (unsigned char *) MapViewOfFile(map_file, // handle to map object
               FILE_MAP_ALL_ACCESS,  // read/write permission
               0,
               0,
               MAP_SIZE);

   if (winafl_data.afl_area == NULL) DR_ASSERT_MSG(false, "error accesing shared memory");
}

static void
options_init(client_id_t id, int argc, const char *argv[])
{
    int i;
    const char *token;
    target_module_t *target_modules;
    /* default values */
	options.persistence_mode = native_mode;
    options.nudge_kills = true;
    options.debug_mode = false;
    options.thread_coverage = false;
    options.coverage_kind = COVERAGE_BB;
    options.target_modules = NULL;
    options.fuzz_module[0] = 0;
    options.fuzz_method[0] = 0;
    options.fuzz_offset = 0;
    options.fuzz_iterations = 1000;
    options.no_loop = false;
    options.func_args = NULL;
    options.num_fuz_args = 0;
    options.callconv = DRWRAP_CALLCONV_DEFAULT;
	options.dr_persist_cache = false;
    dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), ".");

    strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_default");
    strcpy(options.shm_name, "afl_shm_default");

    for (i = 1/*skip client*/; i < argc; i++) {
        token = argv[i];
        if (strcmp(token, "-no_nudge_kills") == 0)
            options.nudge_kills = false;
        else if (strcmp(token, "-nudge_kills") == 0)
            options.nudge_kills = true;
        else if (strcmp(token, "-thread_coverage") == 0)
            options.thread_coverage = true;
        else if (strcmp(token, "-debug") == 0)
            options.debug_mode = true;
        else if (strcmp(token, "-logdir") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing logdir path");
            strncpy(options.logdir, argv[++i], BUFFER_SIZE_ELEMENTS(options.logdir));
        }
        else if (strcmp(token, "-fuzzer_id") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing fuzzer id");
            strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_");
            strcpy(options.shm_name, "afl_shm_");
            strcat(options.pipe_name, argv[i+1]);
            strcat(options.shm_name, argv[i+1]);
            i++;
        }
        else if (strcmp(token, "-covtype") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing coverage type");
            token = argv[++i];
            if(strcmp(token, "bb")==0) options.coverage_kind = COVERAGE_BB;
            else if (strcmp(token, "edge")==0) options.coverage_kind = COVERAGE_EDGE;
            else USAGE_CHECK(false, "invalid coverage type");
        }
        else if (strcmp(token, "-coverage_module") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing module");
            target_modules = options.target_modules;
            options.target_modules = (target_module_t *)dr_global_alloc(sizeof(target_module_t));
            options.target_modules->next = target_modules;
            strncpy(options.target_modules->module_name, argv[++i], BUFFER_SIZE_ELEMENTS(options.target_modules->module_name));
        }
        else if (strcmp(token, "-target_module") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing module");
            strncpy(options.fuzz_module, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_module));
        }
        else if (strcmp(token, "-target_method") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing method");
            strncpy(options.fuzz_method, argv[++i], BUFFER_SIZE_ELEMENTS(options.fuzz_method));
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
        else if (strcmp(token, "-verbose") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing -verbose number");
            token = argv[++i];
            if (dr_sscanf(token, "%u", &verbose) != 1) {
                USAGE_CHECK(false, "invalid -verbose number");
            }
        }
        else if (strcmp(token, "-call_convention") == 0) {
            USAGE_CHECK((i + 1) < argc, "missing calling convention");
            ++i;
            if (strcmp(argv[i], "stdcall") == 0)
                options.callconv = DRWRAP_CALLCONV_CDECL;
            else if (strcmp(argv[i], "fastcall") == 0)
                options.callconv = DRWRAP_CALLCONV_FASTCALL;
            else if (strcmp(argv[i], "thiscall") == 0)
                options.callconv = DRWRAP_CALLCONV_THISCALL;
            else if (strcmp(argv[i], "ms64") == 0)
                options.callconv = DRWRAP_CALLCONV_MICROSOFT_X64;
            else
                NOTIFY(0, "Unknown calling convention, using default value instead.\n");
		}
		else if (strcmp(token, "-no_loop") == 0) {
			options.no_loop = true;
		}
		else if (strcmp(token, "-drpersist") == 0) {
			options.dr_persist_cache = true;
		}
		else if (strcmp(token, "-persistence_mode") == 0) {
			USAGE_CHECK((i + 1) < argc, "missing mode arg: '-fuzz_mode' arg");
			const char* mode = argv[++i];
			if (strcmp(mode, "in_app") == 0)
			{
				options.persistence_mode = in_app;
			}
			else
			{
				options.persistence_mode = native_mode;
			}
		}
        else {
            NOTIFY(0, "UNRECOGNIZED OPTION: \"%s\"\n", token);
            USAGE_CHECK(false, "invalid option");
        }
    }

    if(options.fuzz_module[0] && (options.fuzz_offset == 0) && (options.fuzz_method[0] == 0)) {
       USAGE_CHECK(false, "If fuzz_module is specified, then either fuzz_method or fuzz_offset must be as well");
    }

    if(options.num_fuz_args) {
        options.func_args = (void **)dr_global_alloc(options.num_fuz_args * sizeof(void *));
    }
}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 2 /*max slots needed: aflags*/, false};

    dr_set_client_name("WinAFL", "");

    drmgr_init();
    drx_init();
    drreg_init(&ops);
    drwrap_init();

    options_init(id, argc, argv);

    dr_register_exit_event(event_exit);

    drmgr_register_exception_event(onexception);

    if(options.coverage_kind == COVERAGE_BB) {
        drmgr_register_bb_instrumentation_event(NULL, instrument_bb_coverage, NULL);
    } else if(options.coverage_kind == COVERAGE_EDGE) {
        drmgr_register_bb_instrumentation_event(NULL, instrument_edge_coverage, NULL);
    }

    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
    dr_register_nudge_event(event_nudge, id);

    client_id = id;

    if (options.nudge_kills)
        drx_register_soft_kills(event_soft_kill);

    if(options.thread_coverage) {
        winafl_data.fake_afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
    }

    if(!options.debug_mode) {
        setup_pipe();
        setup_shmem();
    } else {
        winafl_data.afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
    }

    if(options.coverage_kind == COVERAGE_EDGE || options.thread_coverage || options.dr_persist_cache) {
        winafl_tls_field = drmgr_register_tls_field();
        if(winafl_tls_field == -1) {
            DR_ASSERT_MSG(false, "error reserving TLS field");
        }
        drmgr_register_thread_init_event(event_thread_init);
        drmgr_register_thread_exit_event(event_thread_exit);
    }

    event_init();
}
