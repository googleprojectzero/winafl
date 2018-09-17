/*
   american fuzzy lop - test case minimizer
   ----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Windows fork written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Copyright 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A simple test case minimizer that takes an input file and tries to remove
   as much data as possible while keeping the binary in a crashing state
   *or* producing consistent instrumentation output (the mode is auto-selected
   based on the initially observed behavior).

 */
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S
#define AFL_MAIN
#define VERSION             "2.51b"

#include <windows.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <io.h>
#include <direct.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

static s32 child_pid;                 /* PID of the tested program         */

static HANDLE child_handle,
              child_thread_handle;
static char *dynamorio_dir;
static char *client_params;
int fuzz_iterations_max = 1, fuzz_iterations_current;

static CRITICAL_SECTION critical_section;
static u64 watchdog_timeout_time;
static u8 watchdog_enabled;
static u8 *target_cmd;                /* command line of target           */

static u8 *trace_bits,                /* SHM with instrumentation bitmap   */
          *mask_bitmap;               /* Mask for trace bits (-B)          */

static u8 *in_file,                   /* Minimizer input test case         */
          *out_file,                  /* Minimizer output file             */
          *prog_in,                   /* Targeted program input file       */
          *target_path,               /* Path to target binary             */
          *doc_path,                  /* Path to docs                      */
          *at_file;                   /* Substitution string for @@        */

static u8* in_data;                   /* Input data for trimming           */

static u32 in_len,                    /* Input data length                 */
           orig_cksum,                /* Original checksum                 */
           total_execs,               /* Total number of execs             */
           missed_hangs,              /* Misses due to hangs               */
           missed_crashes,            /* Misses due to crashes             */
           missed_paths,              /* Misses due to exec path diffs     */
           exec_tmout = EXEC_TIMEOUT; /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static HANDLE shm_handle;             /* Handle of the SHM region         */
static HANDLE pipe_handle;            /* Handle of the name pipe          */
static u64    name_seed;              /* Random integer to have a unique shm/pipe name */
static HANDLE devnul_handle;          /* Handle of the nul device         */
static u8     sinkhole_stds = 1;      /* Sink-hole stdout/stderr messages?*/
static char   *fuzzer_id = NULL;      /* The fuzzer ID or a randomized 
                                         seed allowing multiple instances */

static u8  crash_mode,                /* Crash-centric mode?               */
           exit_crash,                /* Treat non-zero exit as crash?     */
           edges_only,                /* Ignore hit counts?                */
           exact_mode,                /* Require path match for crashes?   */
           use_stdin = 1,             /* Use stdin for program input?      */
           drioless = 0;

static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out;           /* Child timed out?                  */


/* Classify tuple counts. This is a slow & naive version, but good enough here. */
#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static const u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

static void classify_counts(u8* mem) {

  u32 i = MAP_SIZE;

  if (edges_only) {

    while (i--) {
      if (*mem) *mem = 1;
      mem++;
    }

  } else {

    while (i--) {
      *mem = count_class_lookup[*mem];
      mem++;
    }

  }

}


/* Apply mask to classified bitmap (if set). */

static void apply_mask(u32* mem, u32* mask) {

  u32 i = (MAP_SIZE >> 2);

  if (!mask) return;

  while (i--) {

    *mem &= ~*mask;
    mem++;
    mask++;

  }

}


/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32* ptr = (u32*)trace_bits;
  u32  i   = (MAP_SIZE >> 2);

  while (i--) if (*(ptr++)) return 1;

  return 0;

}


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  u64 ret;
  FILETIME filetime;
  GetSystemTimeAsFileTime(&filetime);

  ret = (((u64)filetime.dwHighDateTime)<<32) + (u64)filetime.dwLowDateTime;

  return ret / 10000;

}


/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  u64 ret;
  FILETIME filetime;
  GetSystemTimeAsFileTime(&filetime);

  ret = (((u64)filetime.dwHighDateTime)<<32) + (u64)filetime.dwLowDateTime;

  return ret / 10;

}


char *alloc_printf(const char *_str, ...) {

  va_list argptr;
  char* _tmp;
  s32 _len;

  va_start(argptr, _str);
  _len = vsnprintf(NULL, 0, _str, argptr);
  if (_len < 0) FATAL("Whoa, snprintf() fails?!");
  _tmp = ck_alloc(_len + 1);
  vsnprintf(_tmp, _len + 1, _str, argptr);
  va_end(argptr);
  return _tmp;

}


/* Get rid of shared memory and temp files (atexit handler). */

static void remove_shm(void) {

  UnmapViewOfFile(trace_bits);
  CloseHandle(shm_handle);
  if (prog_in) unlink(prog_in); /* Ignore errors */

}


/* Configure shared memory. */

static void setup_shm(void) {

  char* shm_str = NULL;
  unsigned int seeds[2];
  u64 name_seed;
  u8 attempts = 0;

  while(attempts < 5) {
    if(fuzzer_id == NULL) {
      // If it is null, it means we have to generate a random seed to name the instance
      rand_s(&seeds[0]);
      rand_s(&seeds[1]);
      name_seed = ((u64)seeds[0] << 32) | seeds[1];
      fuzzer_id = (char *)alloc_printf("%I64x", name_seed);
    }

    shm_str = (char *)alloc_printf("afl_shm_%s", fuzzer_id);

    shm_handle = CreateFileMapping(
                   INVALID_HANDLE_VALUE,    // use paging file
                   NULL,                    // default security
                   PAGE_READWRITE,          // read/write access
                   0,                       // maximum object size (high-order DWORD)
                   MAP_SIZE,                // maximum object size (low-order DWORD)
                   (char *)shm_str);        // name of mapping object

    if(shm_handle == NULL) {
      if(GetLastError() == ERROR_ALREADY_EXISTS) {
        // We need another attempt to find a unique section name
        attempts++;
        ck_free(shm_str);
        ck_free(fuzzer_id);
        fuzzer_id = NULL;
        continue;
      }
      else {
        PFATAL("CreateFileMapping failed");
      }
    }

    // We found a section name that works!
    break;
  }

  if(attempts == 5) {
    FATAL("Could not find a section name.\n");
  }

  atexit(remove_shm);

  ck_free(shm_str);

  trace_bits = (u8 *)MapViewOfFile(
    shm_handle,          // handle to map object
    FILE_MAP_ALL_ACCESS, // read/write permission
    0,
    0,
    MAP_SIZE
  );

  if (!trace_bits) PFATAL("MapViewOfFile() failed");

}


/* Read initial file. */

static void read_initial_file(void) {

  struct stat st;
  s32 fd = _open(in_file, O_RDONLY | O_BINARY);

  if (fd < 0) PFATAL("Unable to open '%s'", in_file);

  if (fstat(fd, &st) || !st.st_size)
    FATAL("Zero-sized input file.");

  if (st.st_size >= TMIN_MAX_FILE)
    FATAL("Input file is too large (%u MB max)", TMIN_MAX_FILE / 1024 / 1024);

  in_len  = st.st_size;
  in_data = ck_alloc_nozero(in_len);

  ck_read(fd, in_data, in_len, in_file);

  _close(fd);

  OKF("Read %u byte%s from '%s'.", in_len, in_len == 1 ? "" : "s", in_file);

}


/* Write output file. */

static void write_to_file(u8* path, u8* mem, u32 len) {

  s32 ret;

  _unlink(path); /* Ignore errors */

  ret = _open(path, O_RDWR | O_CREAT | O_EXCL | O_BINARY, 0600);

  if (ret < 0) PFATAL("Unable to create '%s'", path);

  ck_write(ret, mem, len, path);

  _lseek(ret, 0, SEEK_SET);
  _close(ret);

}

//quoting on Windows is weird
size_t ArgvQuote(char *in, char *out) {
  int needs_quoting = 0;
  size_t size = 0;
  char *p = in;
  size_t i;

  //check if quoting is necessary
  if(strchr(in, ' ')) needs_quoting = 1;
  if(strchr(in, '\"')) needs_quoting = 1;
  if(strchr(in, '\t')) needs_quoting = 1;
  if(strchr(in, '\n')) needs_quoting = 1;
  if(strchr(in, '\v')) needs_quoting = 1;
  if(!needs_quoting) {
    size = strlen(in);
    if(out) memcpy(out, in, size);
    return size;
  }

  if(out) out[size] = '\"';
  size++;

  while(*p) {
    size_t num_backslashes = 0;
    while((*p) && (*p == '\\')) {
      p++;
      num_backslashes++;
    }

    if(*p == 0) {
      for(i = 0; i < (num_backslashes*2); i++) {
        if(out) out[size] = '\\';
        size++;
      }
      break;
    } else if(*p == '\"') {
      for(i = 0; i < (num_backslashes*2 + 1); i++) {
        if(out) out[size] = '\\';
        size++;
      }
      if(out) out[size] = *p;
      size++;
    } else {
      for(i = 0; i < num_backslashes; i++) {
        if(out) out[size] = '\\';
        size++;
      }
      if(out) out[size] = *p;
      size++;
    }

    p++;
  }

  if(out) out[size] = '\"';
  size++;

  return size;
}


char *argv_to_cmd(char** argv) {
  u32 len = 0, i;
  u8* buf, *ret;

  //todo shell-escape

  for (i = 0; argv[i]; i++)
    len += ArgvQuote(argv[i], NULL) + 1;

  if(!len) FATAL("Error creating command line");

  buf = ret = ck_alloc(len);

  for (i = 0; argv[i]; i++) {

    u32 l = ArgvQuote(argv[i], buf);

    buf += l;

    *(buf++) = ' ';
  }

  ret[len-1] = 0;

  return ret;
}


static void create_target_process(char** argv) {
  char* cmd;
  char* pipe_name;
  char *buf;
  char *pidfile = NULL;
  FILE *fp;
  size_t pidsize;
  BOOL inherit_handles = TRUE;
  HANDLE hJob = NULL;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION job_limit;

  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  pipe_name = (char *)alloc_printf("\\\\.\\pipe\\afl_pipe_%s", fuzzer_id);

  pipe_handle = CreateNamedPipe(
    pipe_name,                // pipe name
    PIPE_ACCESS_DUPLEX,       // read/write access
    0,
    1,                        // max. instances
    512,                      // output buffer size
    512,                      // input buffer size
    20000,                    // client time-out
    NULL);                    // default security attribute

  if (pipe_handle == INVALID_HANDLE_VALUE) {
    FATAL("CreateNamedPipe failed, GLE=%d.\n", GetLastError());
  }

  target_cmd = argv_to_cmd(argv);

  if (drioless) {
    char *static_config = alloc_printf("%s:1", fuzzer_id);

    if (static_config == NULL) {
      FATAL("Cannot allocate static_config.");
    }

    SetEnvironmentVariable("AFL_STATIC_CONFIG", static_config);
    cmd = alloc_printf("%s", target_cmd);
    ck_free(static_config);
  } else {
    pidfile = alloc_printf("childpid_%s.txt", fuzzer_id);
    cmd = alloc_printf(
      "%s\\drrun.exe -pidfile %s -no_follow_children -c winafl.dll %s -fuzz_iterations 1 -fuzzer_id %s -- %s",
      dynamorio_dir, pidfile, client_params, fuzzer_id, target_cmd
    );
  }

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if (sinkhole_stds) {
    si.hStdOutput = si.hStdError = devnul_handle;
    si.dwFlags |= STARTF_USESTDHANDLES;
  } else {
    inherit_handles = FALSE;
  }

  if (mem_limit != 0) {
    hJob = CreateJobObject(NULL, NULL);
    if (hJob == NULL) {
      FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
    }

    ZeroMemory(&job_limit, sizeof(job_limit));
    job_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    job_limit.ProcessMemoryLimit = mem_limit * 1024 * 1024;

    if (!SetInformationJobObject(
      hJob,
      JobObjectExtendedLimitInformation,
      &job_limit,
      sizeof(job_limit)
    )) {
      FATAL("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  if (!CreateProcess(NULL, cmd, NULL, NULL, inherit_handles, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
  }

  child_handle = pi.hProcess;
  child_thread_handle = pi.hThread;

  if (mem_limit != 0) {
    if (!AssignProcessToJobObject(hJob, child_handle)) {
      FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  ResumeThread(child_thread_handle);

  watchdog_timeout_time = get_cur_time() + exec_tmout;
  watchdog_enabled = 1;

  if (!ConnectNamedPipe(pipe_handle, NULL)) {
    if (GetLastError() != ERROR_PIPE_CONNECTED) {
      FATAL("ConnectNamedPipe failed, GLE=%d.\n", GetLastError());
    }
  }

  watchdog_enabled = 0;

  if (drioless == 0) {
    //by the time pipe has connected the pidfile must have been created
    fp = fopen(pidfile, "rb");
    if (!fp) {
      FATAL("Error opening pidfile.txt");
    }
    fseek(fp,0,SEEK_END);
    pidsize = ftell(fp);
    fseek(fp,0,SEEK_SET);
    buf = (char *)malloc(pidsize+1);
    fread(buf, pidsize, 1, fp);
    buf[pidsize] = 0;
    fclose(fp);
    remove(pidfile);
    child_pid = atoi(buf);
    free(buf);
    ck_free(pidfile);
  }
  else {
    child_pid = pi.dwProcessId;
  }

  ck_free(target_cmd);
  ck_free(cmd);
  ck_free(pipe_name);
}


static void destroy_target_process(int wait_exit) {
  char* kill_cmd;
  BOOL still_alive = TRUE;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  EnterCriticalSection(&critical_section);

  if(!child_handle) {
    goto leave;
  }

  if(WaitForSingleObject(child_handle, wait_exit) != WAIT_TIMEOUT) {
    goto done;
  }

  // nudge the child process only if dynamorio is used
  if(drioless) {
    TerminateProcess(child_handle, 0);
  } else {
    kill_cmd = alloc_printf("%s\\drconfig.exe -nudge_pid %d 0 1", dynamorio_dir, child_pid);

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if(!CreateProcess(NULL, kill_cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    ck_free(kill_cmd);
  }

  still_alive = WaitForSingleObject(child_handle, 2000) == WAIT_TIMEOUT;

  if(still_alive) {
    //wait until the child process exits
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    kill_cmd = alloc_printf("taskkill /PID %d /F", child_pid);

    if(!CreateProcess(NULL, kill_cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    ck_free(kill_cmd);

    if(WaitForSingleObject(child_handle, 20000) == WAIT_TIMEOUT) {
      FATAL("Cannot kill child process\n");
    }
  }

  done:
  CloseHandle(child_handle);
  CloseHandle(child_thread_handle);

  child_handle = NULL;
  child_thread_handle = NULL;

  leave:
  //close the pipe
  if(pipe_handle) {
    DisconnectNamedPipe(pipe_handle);
    CloseHandle(pipe_handle);

    pipe_handle = NULL;
  }

  LeaveCriticalSection(&critical_section);
}


DWORD WINAPI watchdog_timer( LPVOID lpParam ) {
  u64 current_time;
  while(1) {
    Sleep(1000);
    current_time = get_cur_time();
    if(watchdog_enabled && (current_time > watchdog_timeout_time)) {
      child_timed_out = 1;
      destroy_target_process(0);
    }
  }
}


static void setup_watchdog_timer() {
  watchdog_enabled = 0;
  InitializeCriticalSection(&critical_section);
  CreateThread(NULL, 0, watchdog_timer, 0, 0, NULL);
}


static int is_child_running() {
   return (child_handle && (WaitForSingleObject(child_handle, 0 ) == WAIT_TIMEOUT));
}


/* Execute target application. Returns 0 if the changes are a dud, or
   1 if they should be kept. */

static u8 run_target(char** argv, u8* mem, u32 len, u8 first_run) {

  char command[] = "F";
  DWORD num_read;
  char result = 0;
  u8 child_crashed;
  u32 cksum;

  write_to_file(prog_in, mem, len);

  if(!is_child_running()) {
    destroy_target_process(0);
    create_target_process(argv);
    fuzz_iterations_current = 0;
  }

  child_timed_out = 0;
  memset(trace_bits, 0, MAP_SIZE);
  MemoryBarrier();

  //TEMPORARY FIX FOR REGULAR USAGE OF AFL-TMIN
  ReadFile(pipe_handle, &result, 1, &num_read, NULL);
  if (result == 'K')
  {
	  //a workaround for first cycle
	  ReadFile(pipe_handle, &result, 1, &num_read, NULL);
  }
  if (result != 'P')
  {
	  FATAL("Unexpected result from pipe! expected 'P', instead received '%c'\n", result);
  }
  //END OF TEMPORARY FIX FOR REGULAR USAGE OF AFL-TMIN
  WriteFile(
    pipe_handle,  // handle to pipe
    command,      // buffer to write from
    1,            // number of bytes to write
    &num_read,    // number of bytes written
    NULL);        // not overlapped I/O

  watchdog_timeout_time = get_cur_time() + exec_tmout;

  if(exec_tmout) {
    watchdog_enabled = 1;
  }

  ReadFile(pipe_handle, &result, 1, &num_read, NULL);

  if(exec_tmout) {
    watchdog_enabled = 0;
  }

  MemoryBarrier();

  /* Clean up bitmap, analyze exit condition, etc. */

  classify_counts(trace_bits);
  apply_mask((u32*)trace_bits, (u32*)mask_bitmap);
  total_execs++;
  fuzz_iterations_current++;

  if(fuzz_iterations_current == fuzz_iterations_max) {
    destroy_target_process(2000);
  }

  if (stop_soon) {
    SAYF(cRST cLRD "\n+++ Minimization aborted by user +++\n" cRST);
    exit(1);
  }

  child_crashed = result == 'C';

  /* Always discard inputs that time out. */

  if (child_timed_out) {

    missed_hangs++;
    return 0;

  }

  /* Handle crashing inputs depending on current mode. */

  if (child_crashed) {

    if (first_run) crash_mode = 1;

    if (crash_mode) {

      if (!exact_mode) return 1;

    } else {

      missed_crashes++;
      return 0;

    }

  } else

  /* Handle non-crashing inputs appropriately. */

  if (crash_mode) {

    missed_paths++;
    return 0;

  }

  cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  if (first_run) orig_cksum = cksum;

  if (orig_cksum == cksum) return 1;

  missed_paths++;
  return 0;

}


/* Find first power of two greater or equal to val. */

static u32 next_p2(u32 val) {

  u32 ret = 1;
  while (val > ret) ret <<= 1;
  return ret;

}


/* Actually minimize! */

static void minimize(char** argv) {

  static u32 alpha_map[256];

  u8* tmp_buf = ck_alloc_nozero(in_len);
  u32 orig_len = in_len, stage_o_len;

  u32 del_len, set_len, del_pos, set_pos, i, alpha_size, cur_pass = 0;
  u32 syms_removed, alpha_del0 = 0, alpha_del1, alpha_del2, alpha_d_total = 0;
  u8  changed_any, prev_del;

  /***********************
   * BLOCK NORMALIZATION *
   ***********************/

  set_len    = next_p2(in_len / TMIN_SET_STEPS);
  set_pos    = 0;

  if (set_len < TMIN_SET_MIN_SIZE) set_len = TMIN_SET_MIN_SIZE;

  ACTF(cBRI "Stage #0: " cRST "One-time block normalization...");

  while (set_pos < in_len) {

    u8  res;
    u32 use_len = MIN(set_len, in_len - set_pos);

    for (i = 0; i < use_len; i++)
      if (in_data[set_pos + i] != '0') break;

    if (i != use_len) {

      memcpy(tmp_buf, in_data, in_len);
      memset(tmp_buf + set_pos, '0', use_len);

      res = run_target(argv, tmp_buf, in_len, 0);

      if (res) {

        memset(in_data + set_pos, '0', use_len);
        changed_any = 1;
        alpha_del0 += use_len;

      }

    }

    set_pos += set_len;

  }

  alpha_d_total += alpha_del0;

  OKF("Block normalization complete, %u byte%s replaced.", alpha_del0,
      alpha_del0 == 1 ? "" : "s");

next_pass:

  ACTF(cYEL "--- " cBRI "Pass #%u " cYEL "---", ++cur_pass);
  changed_any = 0;

  /******************
   * BLOCK DELETION *
   ******************/

  del_len = next_p2(in_len / TRIM_START_STEPS);
  stage_o_len = in_len;

  ACTF(cBRI "Stage #1: " cRST "Removing blocks of data...");

next_del_blksize:

  if (!del_len) del_len = 1;
  del_pos  = 0;
  prev_del = 1;

  SAYF(cGRA "    Block length = %u, remaining size = %u\n" cRST,
       del_len, in_len);

  while (del_pos < in_len) {

    u8  res;
    s32 tail_len;

    tail_len = in_len - del_pos - del_len;
    if (tail_len < 0) tail_len = 0;

    /* If we have processed at least one full block (initially, prev_del == 1),
       and we did so without deleting the previous one, and we aren't at the
       very end of the buffer (tail_len > 0), and the current block is the same
       as the previous one... skip this step as a no-op. */

    if (!prev_del && tail_len && !memcmp(in_data + del_pos - del_len,
        in_data + del_pos, del_len)) {

      del_pos += del_len;
      continue;

    }

    prev_del = 0;

    /* Head */
    memcpy(tmp_buf, in_data, del_pos);

    /* Tail */
    memcpy(tmp_buf + del_pos, in_data + del_pos + del_len, tail_len);

    res = run_target(argv, tmp_buf, del_pos + tail_len, 0);

    if (res) {

      memcpy(in_data, tmp_buf, del_pos + tail_len);
      prev_del = 1;
      in_len   = del_pos + tail_len;

      changed_any = 1;

    } else del_pos += del_len;

  }

  if (del_len > 1 && in_len >= 1) {

    del_len /= 2;
    goto next_del_blksize;

  }

  OKF("Block removal complete, %u bytes deleted.", stage_o_len - in_len);

  if (!in_len && changed_any)
    WARNF(cLRD "Down to zero bytes - check the command line and mem limit!" cRST);

  if (cur_pass > 1 && !changed_any) goto finalize_all;

  /*************************
   * ALPHABET MINIMIZATION *
   *************************/

  alpha_size   = 0;
  alpha_del1   = 0;
  syms_removed = 0;

  memset(alpha_map, 0, 256 * sizeof(u32));

  for (i = 0; i < in_len; i++) {
    if (!alpha_map[in_data[i]]) alpha_size++;
    alpha_map[in_data[i]]++;
  }

  ACTF(cBRI "Stage #2: " cRST "Minimizing symbols (%u code point%s)...",
       alpha_size, alpha_size == 1 ? "" : "s");

  for (i = 0; i < 256; i++) {

    u32 r;
    u8 res;

    if (i == '0' || !alpha_map[i]) continue;

    memcpy(tmp_buf, in_data, in_len);

    for (r = 0; r < in_len; r++)
      if (tmp_buf[r] == i) tmp_buf[r] = '0';

    res = run_target(argv, tmp_buf, in_len, 0);

    if (res) {

      memcpy(in_data, tmp_buf, in_len);
      syms_removed++;
      alpha_del1 += alpha_map[i];
      changed_any = 1;

    }

  }

  alpha_d_total += alpha_del1;

  OKF("Symbol minimization finished, %u symbol%s (%u byte%s) replaced.",
      syms_removed, syms_removed == 1 ? "" : "s",
      alpha_del1, alpha_del1 == 1 ? "" : "s");

  /**************************
   * CHARACTER MINIMIZATION *
   **************************/

  alpha_del2 = 0;

  ACTF(cBRI "Stage #3: " cRST "Character minimization...");

  memcpy(tmp_buf, in_data, in_len);

  for (i = 0; i < in_len; i++) {

    u8 res, orig = tmp_buf[i];

    if (orig == '0') continue;
    tmp_buf[i] = '0';

    res = run_target(argv, tmp_buf, in_len, 0);

    if (res) {

      in_data[i] = '0';
      alpha_del2++;
      changed_any = 1;

    } else tmp_buf[i] = orig;

  }

  alpha_d_total += alpha_del2;

  OKF("Character minimization done, %u byte%s replaced.",
      alpha_del2, alpha_del2 == 1 ? "" : "s");

  if (changed_any) goto next_pass;

finalize_all:

  SAYF("\n"
       cGRA "     File size reduced by : " cRST "%0.02f%% (to %u byte%s)\n"
       cGRA "    Characters simplified : " cRST "%0.02f%%\n"
       cGRA "     Number of execs done : " cRST "%u\n"
       cGRA "          Fruitless execs : " cRST "path=%u crash=%u hang=%s%u\n\n",
       100 - ((double)in_len) * 100 / orig_len, in_len, in_len == 1 ? "" : "s",
       ((double)(alpha_d_total)) * 100 / (in_len ? in_len : 1),
       total_execs, missed_paths, missed_crashes, missed_hangs ? cLRD : "",
       missed_hangs);

  if (total_execs > 50 && missed_hangs * 10 > total_execs)
    WARNF(cLRD "Frequent timeouts - results may be skewed." cRST);

}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

  if (sinkhole_stds) {
    devnul_handle = CreateFile(
      "nul",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL
    );

    if (devnul_handle == INVALID_HANDLE_VALUE) {
      PFATAL("Unable to open the nul device.");
    }
  }

  if (!prog_in) {

    u8* use_dir = getenv("TMP");
    prog_in = alloc_printf("%s\\.afl-tmin-temp-%u", use_dir, getpid());

  }

}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {
  // not implemented on Windows
}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = getcwd(NULL, 0);

  if (!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      u8 *aa_subst, *n_arg;

      aa_subst = prog_in;

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      //if (out_file[0] != '\\') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- [instrumentation options] -- \\path\\to\\target_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i file       - input test case to be shrunk by the tool\n"
       "  -o file       - final output location for the minimized data\n\n"

       "Instrumentation type:\n\n"
       "  -D dir        - directory with DynamoRIO binaries (drrun, drconfig)\n"
       "  -Y            - enable the static instrumentation mode\n\n"

       "Execution control settings:\n\n"

       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"

       "Minimization settings:\n\n"

       "  -e            - solve for edge coverage only, ignore hit counts\n"
       "  -x            - treat non-zero exit codes as crashes\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Find binary. */

static void find_binary(u8* fname) {
  // Not implemented on Windows
}


/* Read mask bitmap from file. This is for the -B option. */

static void read_bitmap(u8* fname) {

  s32 fd = _open(fname, O_RDONLY | O_BINARY);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);

  ck_read(fd, mask_bitmap, MAP_SIZE, fname);

  _close(fd);

}

static unsigned int optind;
static char *optarg;

int getopt(int argc, char **argv, char *optstring) {
  char *c;

  optarg = NULL;

  while(1) {
    if(optind == argc) return -1;
    if(strcmp(argv[optind], "--") == 0) return -1;
    if(argv[optind][0] != '-') {
      optind++;
      continue;
    }
    if(!argv[optind][1]) {
      optind++;
      continue;
    }

    c = strchr(optstring, argv[optind][1]);
    if(!c) return -1;
    optind++;
    if(c[1] == ':') {
      if(optind == argc) return -1;
      optarg = argv[optind];
      optind++;
    }

    return (int)(c[0]);
  }
}


static void extract_client_params(u32 argc, char** argv) {
  u32 len = 1, i;
  u32 nclientargs = 0;
  u8* buf;
  u32 opt_start, opt_end;

  if(!argv[optind] || optind >= argc) usage(argv[0]);
  if(strcmp(argv[optind],"--")) usage(argv[0]);

  if(drioless) return;
  optind++;
  opt_start = optind;

  for (i = optind; i < argc; i++) {
    if(strcmp(argv[i],"--") == 0) break;
    nclientargs++;
    len += strlen(argv[i]) + 1;
  }

  if(i == argc) usage(argv[0]);
  opt_end = i;

  buf = client_params = ck_alloc(len);

  for (i = opt_start; i < opt_end; i++) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    *(buf++) = ' ';
  }

  if(buf != client_params) {
    buf--;
  }

  *buf = 0;

  optind = opt_end;

}


/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u8  mem_limit_given = 0, timeout_given = 0;
  char** use_argv;

  doc_path = "docs";
  optind = 1;
  dynamorio_dir = NULL;
  client_params = NULL;

#ifdef USE_COLOR
  enable_ansi_console();
#endif

  SAYF(cCYA "afl-tmin for Windows " cBRI VERSION cRST " by <0vercl0k@tuxfamily.org>\n");
  SAYF("Based on WinAFL " cBRI VERSION cRST " by <ifratric@google.com>\n");
  SAYF("Based on AFL " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

  while ((opt = getopt(argc,argv,"+i:o:f:m:t:B:D:xeQY")) > 0)

    switch (opt) {

      case 'D': /* dynamorio dir */

        if(dynamorio_dir) FATAL("Multiple -D options not supported");
        dynamorio_dir = optarg;
        break;

      case 'i':

        if (in_file) FATAL("Multiple -i options not supported");
        in_file = optarg;
        break;

      case 'o':

        if (out_file) FATAL("Multiple -o options not supported");
        out_file = optarg;
        break;

      case 'f':

        if (prog_in) FATAL("Multiple -f options not supported");
        use_stdin = 0;
        prog_in   = optarg;
        break;

      case 'e':

        if (edges_only) FATAL("Multiple -e options not supported");
        edges_only = 1;
        break;

      case 'x':

        if (exit_crash) FATAL("Multiple -x options not supported");
        exit_crash = 1;
        break;

      case 'm': {

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(int) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        exec_tmout = atoi(optarg);

        if (exec_tmout < 10 || optarg[0] == '-')
          FATAL("Dangerously low value of -t");

        break;

      case 'B': /* load bitmap */

        /* This is a secret undocumented option! It is speculated to be useful
           if you have a baseline "boring" input file and another "interesting"
           file you want to minimize.

           You can dump a binary bitmap for the boring file using
           afl-showmap -b, and then load it into afl-tmin via -B. The minimizer
           will then minimize to preserve only the edges that are unique to
           the interesting input file, but ignoring everything from the
           original map.

           The option may be extended and made more official if it proves
           to be useful. */

        if (mask_bitmap) FATAL("Multiple -B options not supported");
        mask_bitmap = ck_alloc(MAP_SIZE);
        read_bitmap(optarg);
        break;

      case 'Q':
        FATAL("QEMU mode not supported on Windows");
        break;

      case 'Y':

        if (dynamorio_dir) FATAL("Dynamic-instrumentation via DRIO is uncompatible with static-instrumentation");
        drioless = 1;

        break;

      default:

        usage(argv[0]);

    }

  if(!in_file || !out_file) usage(argv[0]);
  if(!drioless) {
    if(optind == argc || !dynamorio_dir) usage(argv[0]);
  }

  extract_client_params(argc, argv);
  optind++;

  if (getenv("AFL_NO_SINKHOLE")) sinkhole_stds = 0;
  if (getenv("AFL_TMIN_EXACT")) exact_mode = 1;

  setup_shm();
  setup_watchdog_timer();
  setup_signal_handlers();

  set_up_environment();

  find_binary(argv[optind]);
  detect_file_args(argv + optind);

  use_argv = argv + optind;

  SAYF("\n");

  read_initial_file();

  ACTF("Performing dry run (mem limit = %llu MB, timeout = %u ms%s)...",
       mem_limit, exec_tmout, edges_only ? ", edges only" : "");

  run_target(use_argv, in_data, in_len, 1);

  if (child_timed_out)
    FATAL("Target binary times out (adjusting -t may help).");

  if (!crash_mode) {

     OKF("Program terminates normally, minimizing in "
         cCYA "instrumented" cRST " mode.");

     if (!anything_set()) FATAL("No instrumentation detected.");

  } else {

     OKF("Program exits with a signal, minimizing in " cMGN "%scrash" cRST
         " mode.", exact_mode ? "EXACT " : "");

  }

  minimize(use_argv);

  ACTF("Writing output to '%s'...", out_file);

  unlink(prog_in);
  prog_in = NULL;

  write_to_file(out_file, in_data, in_len);

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}
