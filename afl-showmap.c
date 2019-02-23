/*
   american fuzzy lop - map display utility
   ----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Windows fork written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Copyright 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.

*/
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S  
#define VERSION             "2.36b"

#define AFL_MAIN

#include <windows.h>
#include <stdarg.h>
#include <io.h>
#include <direct.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

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

static CRITICAL_SECTION critical_section;
static u64 watchdog_timeout_time;
static u8 watchdog_enabled;
static u8 *target_cmd;                /* command line of target           */

static HANDLE shm_handle;             /* Handle of the SHM region         */
static HANDLE pipe_handle;            /* Handle of the name pipe          */
static u64    name_seed;              /* Random integer to have a unique shm/pipe name */
static HANDLE devnul_handle;          /* Handle of the nul device         */
static char   *fuzzer_id = NULL;      /* The fuzzer ID or a randomized 
                                         seed allowing multiple instances */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *out_file,                  /* Trace output file                 */
          *doc_path,                  /* Path to docs                      */
          *target_path,               /* Path to target binary             */
          *at_file;                   /* Substitution string for @@        */

static u32 exec_tmout;                /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

// static s32 shm_id;                    /* ID of the SHM region              */

static u8  quiet_mode,                /* Hide non-essential messages?      */
           edges_only,                /* Ignore hit counts?                */
           cmin_mode,                 /* Generate output in afl-cmin mode? */
           binary_mode,               /* Write output as a binary map      */
           drioless = 0;              /* Running without DRIO?             */

static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out,           /* Child timed out?                  */
           child_crashed;             /* Child crashed?                    */

/* Classify tuple counts. Instead of mapping to individual bits, as in
   afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

static const u8 count_class_human[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 3,
  /* 4 - 7:      +4 */ AREP4(4),
  /* 8 - 15:     +8 */ AREP8(5),
  /* 16 - 31:   +16 */ AREP16(6),
  /* 32 - 127:  +96 */ AREP64(7), AREP32(7),
  /* 128+:     +128 */ AREP128(8)

};

static const u8 count_class_binary[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

static void classify_counts(u8* mem, const u8* map) {

  u32 i = MAP_SIZE;

  if (edges_only) {

    while (i--) {
      if (*mem) *mem = 1;
      mem++;
    }

  } else {

    while (i--) {
     *mem = map[*mem];
      mem++;
    }

  }

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


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

  UnmapViewOfFile(trace_bits);
  CloseHandle(shm_handle);

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


/* Write results. */

static u32 write_results(void) {

  s32 fd;
  u32 i, ret = 0;

  u8  cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
      caa = !!getenv("AFL_CMIN_ALLOW_ANY");

  if (!strncmp(out_file, "/dev/", 5)) {

    fd = _open(out_file, O_WRONLY, 0600);
    if (fd < 0) PFATAL("Unable to open '%s'", out_file);

  } else if (!strcmp(out_file, "-")) {

    fd = _dup(1);
    if (fd < 0) PFATAL("Unable to open stdout");

  } else {

    _unlink(out_file); /* Ignore errors */
    fd = _open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  }

  if (binary_mode) {

    for (i = 0; i < MAP_SIZE; i++)
      if (trace_bits[i]) ret++;

    ck_write(fd, trace_bits, MAP_SIZE, out_file);
    close(fd);

  } else {


    FILE* f = fdopen(fd, "w");

    if (!f) PFATAL("fdopen() failed");

    for (i = 0; i < MAP_SIZE; i++) {

      if (!trace_bits[i]) continue;
      ret++;

      if (cmin_mode) {

        if (child_timed_out) break;
        if (!caa && child_crashed != cco) break;

        fprintf(f, "%u%u\n", trace_bits[i], i);

      } else fprintf(f, "%06u:%u\n", i, trace_bits[i]);

    }
  
    fclose(f);

  }

  return ret;

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
  char *cmd;
  char *pipe_name;
  char *buf;
  char *pidfile;
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

  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));

  if(quiet_mode) {
    si.hStdOutput = si.hStdError = devnul_handle;
    si.dwFlags |= STARTF_USESTDHANDLES;
  } else {
    inherit_handles = FALSE;
  }

  if(drioless) {
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

  if(mem_limit != 0) {
    hJob = CreateJobObject(NULL, NULL);
    if(hJob == NULL) {
      FATAL("CreateJobObject failed, GLE=%d.\n", GetLastError());
    }

    ZeroMemory(&job_limit, sizeof(job_limit));
    job_limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    job_limit.ProcessMemoryLimit = mem_limit * 1024 * 1024;

    if(!SetInformationJobObject(
      hJob,
      JobObjectExtendedLimitInformation,
      &job_limit,
      sizeof(job_limit)
    )) {
      FATAL("SetInformationJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  if(!CreateProcess(NULL, cmd, NULL, NULL, inherit_handles, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
    FATAL("CreateProcess failed, GLE=%d.\n", GetLastError());
  }

  child_handle = pi.hProcess;
  child_thread_handle = pi.hThread;

  if(mem_limit != 0) {
    if(!AssignProcessToJobObject(hJob, child_handle)) {
      FATAL("AssignProcessToJobObject failed, GLE=%d.\n", GetLastError());
    }
  }

  ResumeThread(child_thread_handle);

  watchdog_timeout_time = get_cur_time() + exec_tmout;
  watchdog_enabled = 1;

  if(!ConnectNamedPipe(pipe_handle, NULL)) {
    if(GetLastError() != ERROR_PIPE_CONNECTED) {
      FATAL("ConnectNamedPipe failed, GLE=%d.\n", GetLastError());
    }
  }

  watchdog_enabled = 0;

  if(drioless == 0) {
    //by the time pipe has connected the pidfile must have been created
    fp = fopen(pidfile, "rb");
    if(!fp) {
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


/* Execute target application. */

static void run_target(char** argv) {

  char command[] = "F";
  DWORD num_read;
  char result = 0;

  if(!quiet_mode)
    SAYF("-- Program output begins --\n" cRST);

  if(quiet_mode && devnul_handle == INVALID_HANDLE_VALUE) {
    devnul_handle = CreateFile(
      "nul",
      GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      NULL,
      OPEN_EXISTING,
      0,
      NULL);

    if(devnul_handle == INVALID_HANDLE_VALUE) {
      PFATAL("Unable to open the nul device.");
    }
  }

  if(!is_child_running()) {
    destroy_target_process(0);
    create_target_process(argv);
  }

  child_timed_out = 0;
  memset(trace_bits, 0, MAP_SIZE);

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

  classify_counts(trace_bits, binary_mode ?
                  count_class_binary : count_class_human);

  if(!quiet_mode)
    SAYF(cRST "-- Program output ends --\n");

  child_crashed = result == 'C';

  if(!quiet_mode) {
    if(result == 'K')
      SAYF(cLRD "\n--- Program finished properly ---\n" cRST);
    else if(child_timed_out)
      SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
    else if(stop_soon)
      SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
    else if(child_crashed)
      SAYF(cLRD "\n+++ Program crashed +++\n" cRST);
  }


}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {
  // Not supported on Windows
}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {
  // not implemented on Windows
}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = _getcwd(NULL, 0);

  if(!cwd) PFATAL("getcwd() failed");

  while (argv[i]) {

    u8* aa_loc = strstr(argv[i], "@@");

    if(aa_loc) {

      u8 *aa_subst, *n_arg;

      if(!at_file) FATAL("@@ syntax is not supported by this tool.");

      /* Be sure that we're always using fully-qualified paths. */

      // if(at_file[0] == '/') aa_subst = at_file;
      // else aa_subst = alloc_printf("%s/%s", cwd, at_file);
      aa_subst = out_file;

      /* Construct a replacement argv value. */

      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      // if(at_file[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Show banner. */

static void show_banner(void) {

  SAYF(cCYA "afl-showmap for Windows " cBRI VERSION cRST " by <0vercl0k@tuxfamily.org>\n");
  SAYF("Based on WinAFL " cBRI VERSION cRST " by <ifratric@google.com>\n");
  SAYF("Based on AFL " cBRI VERSION cRST " by <lcamtuf@google.com>\n");

}

/* Display usage hints. */

static void usage(u8* argv0) {

  show_banner();

  SAYF("\n%s [ options ] -- [instrumentation options] -- \\path\\to\\target_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -o file       - file to write the trace data to\n"

       "Instrumentation type:\n\n"
       "  -D dir        - directory with DynamoRIO binaries (drrun, drconfig)\n"
       "  -Y            - enable the static instrumentation mode\n\n"

       "Execution control settings:\n\n"

       "  -t msec       - timeout for each run (none)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"

       "Other settings:\n\n"

       "  -q            - sink program's output and don't show messages\n"
       "  -e            - show edge coverage only, ignore hit counts\n\n"

       "This tool displays raw tuple data captured by AFL instrumentation.\n"
       "For additional help, consult %s\\README.\n\n" cRST,

       argv0, MEM_LIMIT, doc_path);

  exit(1);

}


/* Find binary. */

static void find_binary(u8* fname) {
  // Not implemented on Windows
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
  u32 tcnt;
  int i = 0, counter = 0;
  char** use_argv;

  doc_path = "docs";
  optind = 1;
  dynamorio_dir = NULL;
  client_params = NULL;

#ifdef USE_COLOR
  enable_ansi_console();
#endif

  while ((opt = getopt(argc, argv, "+o:m:t:A:D:eqZQbY")) > 0)

    switch (opt) {

      case 'D': /* dynamorio dir */

        if(dynamorio_dir) FATAL("Multiple -D options not supported");
        dynamorio_dir = optarg;
        break;

      case 'o':

        if(out_file) FATAL("Multiple -o options not supported");
        out_file = optarg;
        break;

      case 'm': {

          u8 suffix = 'M';

          if(mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if(!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if(sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if(mem_limit < 5) FATAL("Dangerously low value of -m");

          if(sizeof(int) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 't':

        if(timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        if(strcmp(optarg, "none")) {
          exec_tmout = atoi(optarg);

          if(exec_tmout < 20 || optarg[0] == '-')
            FATAL("Dangerously low value of -t");

        }

        break;

      case 'e':

        if(edges_only) FATAL("Multiple -e options not supported");
        edges_only = 1;
        break;

      case 'q':

        if(quiet_mode) FATAL("Multiple -q options not supported");
        quiet_mode = 1;
        break;

      case 'Z':

        /* This is an undocumented option to write data in the syntax expected
           by afl-cmin. Nobody else should have any use for this. */

        cmin_mode  = 1;
        quiet_mode = 1;
        break;

      case 'A':

        FATAL("-A option not supported on Windows");
        /* Another afl-cmin specific feature. */
        at_file = optarg;
        break;

      case 'Q':
        FATAL("QEMU mode not supported on Windows");
        break;

      case 'b':

        /* Secret undocumented mode. Writes output in raw binary format
           similar to that dumped by afl-fuzz in <out_dir/queue/fuzz_bitmap. */

        binary_mode = 1;

      case 'Y':

        if (dynamorio_dir) FATAL("Dynamic-instrumentation (DRIO) is uncompatible with static-instrumentation");
        drioless = 1;
        break;

      default:

        usage(argv[0]);

    }

  if(!out_file) usage(argv[0]);
  if(!drioless) {
    if(optind == argc || !dynamorio_dir) usage(argv[0]);
  }

  extract_client_params(argc, argv);
  optind++;

  setup_shm();
  setup_watchdog_timer();
  setup_signal_handlers();

  set_up_environment();

  find_binary(argv[optind]);

  if(!quiet_mode) {
    show_banner();
    // Find the name of the target executable in the arguments
    for(; i < argc; i++) {
      if(strcmp(argv[i], "--") == 0) counter++;
      if(counter == (drioless ? 1:2)) {
        if(i != (argc - 1)) {
          target_path = argv[i + 1];
        }
        break;
      }
    }
    ACTF("Executing '%s'...\n", target_path);
  }

  detect_file_args(argv + optind);

  use_argv = argv + optind;

  run_target(use_argv);

  tcnt = write_results();

  if(!quiet_mode) {

    if(!tcnt) SAYF("No instrumentation detected");
    OKF("Captured %u tuples in '%s'." cRST, tcnt, out_file);

  }

  exit(child_crashed * 2 + child_timed_out);

}
