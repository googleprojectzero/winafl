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
#include "modules.h"
#include "utils.h"
#include "hashtable.h"
#include "drtable.h"
#include "limits.h"
#include <string.h>
#include <stdlib.h>

#define UNKNOWN_MODULE_ID USHRT_MAX

static uint verbose;

#define NOTIFY(level, fmt, ...) do {          \
    if (verbose >= (level))                   \
        dr_fprintf(STDERR, fmt, __VA_ARGS__); \
} while (0)

#define OPTION_MAX_LENGTH MAXIMUM_PATH

#define COVERAGE_BB 0
#define COVERAGE_EDGE 1

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
    int coverage_kind;
    char logdir[MAXIMUM_PATH];
    target_module_t *target_modules;
    //char instrument_module[MAXIMUM_PATH];
    char fuzz_module[MAXIMUM_PATH];
    char fuzz_method[MAXIMUM_PATH];
    char pipe_name[MAXIMUM_PATH];
    char shm_name[MAXIMUM_PATH];
    unsigned long fuzz_offset;
    int fuzz_iterations;
    void **func_args;
    int num_fuz_args;
} winafl_option_t;
static winafl_option_t options;

#define NUM_THREAD_MODULE_CACHE 4

typedef struct _winafl_data_t {
    module_entry_t *cache[NUM_THREAD_MODULE_CACHE];
    file_t  log;
    //unsigned char afl_area[MAP_SIZE];
    unsigned char *afl_area;
#ifdef _WIN64
    uint64 previous_offset;
#else
    unsigned int previous_offset;
#endif
} winafl_data_t;
static winafl_data_t winafl_data;

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

static void
dump_winafl_data()
{
    dr_write_file(winafl_data.log, winafl_data.afl_area, MAP_SIZE);
}

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    DWORD num_written;
    DWORD exception_code = excpt->record->ExceptionCode;

    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "Exception caught: %x\n", exception_code);

    if((exception_code == EXCEPTION_ACCESS_VIOLATION) || 
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW)) {
          if(options.debug_mode)
            dr_fprintf(winafl_data.log, "crashed\n");
          if(!options.debug_mode)
            WriteFile(pipe, "C", 1, &num_written, NULL);
          dr_exit_process(1);
    }
    return true;
}


static dr_emit_flags_t
instrument_bb_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc start_pc;
    module_entry_t **mod_entry_cache;
    module_entry_t *mod_entry;
    const char *module_name;
    uint offset;
    target_module_t *target_modules;
    bool should_instrument;

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
        if(strcmp(module_name, target_modules->module_name) == 0) {
            should_instrument = true;
            break;
        }
        target_modules = target_modules->next;
    }
    if(!should_instrument) return DR_EMIT_DEFAULT;

    offset = (uint)(start_pc - mod_entry->data->start);
    offset &= MAP_SIZE - 1;
    
    drreg_reserve_aflags(drcontext, bb, inst);

    instrlist_meta_preinsert(bb, inst,
        INSTR_CREATE_inc(drcontext, OPND_CREATE_ABSMEM
        (&(winafl_data.afl_area[offset]), OPSZ_1)));

    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instrument_edge_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                      bool for_trace, bool translating, void *user_data)
{
    app_pc start_pc;
    module_entry_t **mod_entry_cache;
    module_entry_t *mod_entry;
    reg_id_t reg;
#ifdef _WIN64
    reg_id_t reg2;
#endif
    opnd_t opnd1, opnd2;
    instr_t *new_instr;
    const char *module_name;
    uint offset;
    target_module_t *target_modules;
    bool should_instrument;

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
        if(strcmp(module_name, target_modules->module_name) == 0) {
            should_instrument = true;
            break;
        }
        target_modules = target_modules->next;
    }
    if(!should_instrument) return DR_EMIT_DEFAULT;

    offset = (uint)(start_pc - mod_entry->data->start);
    offset &= MAP_SIZE - 1;

    drreg_reserve_aflags(drcontext, bb, inst);
    drreg_reserve_register(drcontext, bb, inst, NULL, &reg);

#ifdef _WIN64

    drreg_reserve_register(drcontext, bb, inst, NULL, &reg2);
    
    //load previous offset into register
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(&(winafl_data.previous_offset), OPSZ_8);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //xor register with the new offset
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //load address of shm into the second register
    opnd1 = opnd_create_reg(reg2);
    opnd2 = OPND_CREATE_INT64((uint64)winafl_data.afl_area);
    new_instr = INSTR_CREATE_mov_imm(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //increase the counter at reg + reg2
    opnd1 = opnd_create_base_disp(reg2, reg, 1, 0, OPSZ_1);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //store the new value
    offset = (offset >> 1)&(MAP_SIZE - 1);
    opnd1 = OPND_CREATE_ABSMEM(&(winafl_data.previous_offset), OPSZ_8);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    drreg_unreserve_register(drcontext, bb, inst, reg2);

#else

    //load previous offset into register
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_ABSMEM(&(winafl_data.previous_offset), OPSZ_4);
    new_instr = INSTR_CREATE_mov_ld(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //xor register with the new offset
    opnd1 = opnd_create_reg(reg);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_xor(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //increase the counter at afl_area+reg
    opnd1 = OPND_CREATE_MEM8(reg, (int)winafl_data.afl_area);
    new_instr = INSTR_CREATE_inc(drcontext, opnd1);
    instrlist_meta_preinsert(bb, inst, new_instr);

    //store the new value
    offset = (offset >> 1)&(MAP_SIZE - 1);
    opnd1 = OPND_CREATE_ABSMEM(&(winafl_data.previous_offset), OPSZ_4);
    opnd2 = OPND_CREATE_INT32(offset);
    new_instr = INSTR_CREATE_mov_st(drcontext, opnd1, opnd2);
    instrlist_meta_preinsert(bb, inst, new_instr);

#endif

    drreg_unreserve_register(drcontext, bb, inst, reg);
    drreg_unreserve_aflags(drcontext, bb, inst);

    return DR_EMIT_DEFAULT;
}

static void
pre_fuzz_handler(void *wrapcxt, INOUT void **user_data)
{
    char command = 0;
    int i;
    DWORD num_read;

    app_pc target_to_fuzz = drwrap_get_func(wrapcxt);
    dr_mcontext_t *mc = drwrap_get_mcontext_ex(wrapcxt, DR_MC_ALL);

    fuzz_target.xsp = mc->xsp;
    fuzz_target.func_pc = target_to_fuzz;

    if(!options.debug_mode) {
        ReadFile(pipe, &command, 1, &num_read, NULL);

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
    if(fuzz_target.iteration == 0) {
        for(i = 0; i < options.num_fuz_args; i++) {
            options.func_args[i] = drwrap_get_arg(wrapcxt, i);
        }
    } else {
        for(i = 0; i < options.num_fuz_args; i++) {
            drwrap_set_arg(wrapcxt, i, options.func_args[i]);
        }
    }

    memset(winafl_data.afl_area, 0, MAP_SIZE);
    winafl_data.previous_offset = 0;
}

static void
post_fuzz_handler(void *wrapcxt, void *user_data)
{
    DWORD num_written;
    dr_mcontext_t *mc = drwrap_get_mcontext(wrapcxt);

    if(!options.debug_mode) {
        WriteFile(pipe, "K", 1, &num_written, NULL);
    } else {
        debug_data.post_handler_called++;
        dr_fprintf(winafl_data.log, "In post_fuzz_handler\n");
    }

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
event_module_unload(void *drcontext, const module_data_t *info)
{
    module_table_unload(module_table, info);
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    const char *module_name = dr_module_preferred_name(info);
    app_pc to_wrap;

    if(options.debug_mode)
        dr_fprintf(winafl_data.log, "Module loaded, %s\n", module_name);

    if(options.fuzz_module[0]) {
        if(strcmp(module_name, options.fuzz_module) == 0) {
            if(options.fuzz_offset) {
                to_wrap = info->start + options.fuzz_offset;
            } else {
                to_wrap = (app_pc)dr_get_proc_address(info->handle, options.fuzz_method);
                DR_ASSERT_MSG(to_wrap, "Can't find specified method in fuzz_module");
            }
            drwrap_wrap(to_wrap, pre_fuzz_handler, post_fuzz_handler);
        }
    
        if(options.debug_mode && (strcmp(module_name, "KERNEL32.dll") == 0)) {
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileW");
            drwrap_wrap(to_wrap, createfilew_interceptor, NULL);
            to_wrap = (app_pc)dr_get_proc_address(info->handle, "CreateFileA");
            drwrap_wrap(to_wrap, createfilea_interceptor, NULL);
        }
    }

    module_table_load(module_table, info);
}

static void
event_exit(void)
{
    if(options.debug_mode) {
        if(debug_data.pre_hanlder_called == 0) {
            dr_fprintf(winafl_data.log, "WARNING: Target function was never called. Incorrect target_offset?\n");
        } else if(debug_data.post_handler_called == 0) {
            dr_fprintf(winafl_data.log, "WARNING: Post-fuzz handler was never reached. Did the target function return normally?\n");
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

    winafl_data.previous_offset = 0;

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
    options.nudge_kills = true;
    options.debug_mode = false;
    options.coverage_kind = COVERAGE_BB;
    options.target_modules = NULL;
    options.fuzz_module[0] = 0;
    options.fuzz_method[0] = 0;
    options.fuzz_offset = 0;
    options.fuzz_iterations = 1000;
    options.func_args = NULL;
    options.num_fuz_args = 0;
    dr_snprintf(options.logdir, BUFFER_SIZE_ELEMENTS(options.logdir), ".");

    strcpy(options.pipe_name, "\\\\.\\pipe\\afl_pipe_default");
    strcpy(options.shm_name, "afl_shm_default");

    for (i = 1/*skip client*/; i < argc; i++) {
        token = argv[i];
        if (strcmp(token, "-no_nudge_kills") == 0)
            options.nudge_kills = false;
        else if (strcmp(token, "-nudge_kills") == 0)
            options.nudge_kills = true;
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

    if(!options.debug_mode) {
        setup_pipe();
        setup_shmem();
    } else {
        winafl_data.afl_area = (unsigned char *)dr_global_alloc(MAP_SIZE);
    }

    event_init();
}
