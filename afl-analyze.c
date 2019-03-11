/*
   american fuzzy lop - file format analyzer
   -----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Windows fork written by @_L4ys

   Based on afl-showmap by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Copyright 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A nifty utility that grabs an input file and takes a stab at explaining
   its structure by observing how changes to it affect the execution path.

   If the output scrolls past the edge of the screen, pipe it to 'less -r'.

 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_RAND_S
#define VERSION             "2.52b"

#define AFL_MAIN

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
#include <fcntl.h>
#include <ctype.h>

#include <sys/stat.h>

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
static u8     sinkhole_stds = 1;      /* Sink-hole stdout/stderr messages?*/
static char   *fuzzer_id = NULL;      /* The fuzzer ID or a randomized
                                         seed allowing multiple instances */

static u8* trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *in_file,                   /* Analyzer input test case          */
          *prog_in,                   /* Targeted program input file       */
          *target_path,               /* Path to target binary             */
          *doc_path;                  /* Path to docs                      */

static u8 *in_data;                   /* Input data for analysis           */

static u32 in_len,                    /* Input data length                 */
           orig_cksum,                /* Original checksum                 */
           total_execs,               /* Total number of execs             */
           exec_hangs,                /* Total number of hangs             */
           exec_tmout = EXEC_TIMEOUT; /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static s32 shm_id,                    /* ID of the SHM region              */
           dev_null_fd = -1;          /* FD to /dev/null                   */

static u8  edges_only,                /* Ignore hit counts?                */
           use_hex_offsets,           /* Show hex offsets?                 */
           use_stdin = 1,             /* Use stdin for program input?      */
           drioless = 0;              /* Running without DRIO?             */


static volatile u8
           stop_soon,                 /* Ctrl-C pressed?                   */
           child_timed_out;           /* Child timed out?                  */


/* Constants used for describing byte behavior. */

#define RESP_NONE       0x00          /* Changing byte is a no-op.         */
#define RESP_MINOR      0x01          /* Some changes have no effect.      */
#define RESP_VARIABLE   0x02          /* Changes produce variable paths.   */
#define RESP_FIXED      0x03          /* Changes produce fixed patterns.   */

#define RESP_LEN        0x04          /* Potential length field            */
#define RESP_CKSUM      0x05          /* Potential checksum                */
#define RESP_SUSPECT    0x06          /* Potential "suspect" blob          */


/* Classify tuple counts. This is a slow & naive version, but good enough here. */
#define AREP4(_sym)   (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym)   AREP4(_sym), AREP4(_sym)
#define AREP16(_sym)  AREP8(_sym), AREP8(_sym)
#define AREP32(_sym)  AREP16(_sym), AREP16(_sym)
#define AREP64(_sym)  AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)
static u8 count_class_lookup[256] = {

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

    ret = (((u64)filetime.dwHighDateTime) << 32) + (u64)filetime.dwLowDateTime;

    return ret / 10000;

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
  if (prog_in) _unlink(prog_in); /* Ignore errors */

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


/* Handle timeout signal. */

/*static void handle_timeout(int sig) {

  child_timed_out = 1;
  if (child_pid > 0) kill(child_pid, SIGKILL);

}*/


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

/* Execute target application. Returns exec checksum, or 0 if program
   times out. */

static u32 run_target(char** argv, u8* mem, u32 len, u8 first_run) {

  int status = 0;
  char command[] = "F";
  DWORD num_read;
  char result = 0;
  u32 cksum;

  memset(trace_bits, 0, MAP_SIZE);
  MemoryBarrier();

  write_to_file(prog_in, mem, len);

  if (!is_child_running()) {
      destroy_target_process(0);
      create_target_process(argv);
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

  if (exec_tmout) {
      watchdog_enabled = 1;
  }

  ReadFile(pipe_handle, &result, 1, &num_read, NULL);

  if (exec_tmout) {
      watchdog_enabled = 0;
  }

  MemoryBarrier();

  /* Clean up bitmap, analyze exit condition, etc. */

  classify_counts(trace_bits);
  total_execs++;

  destroy_target_process(2000);

  if (stop_soon) {
    SAYF(cRST cLRD "\n+++ Analysis aborted by user +++\n" cRST);
    exit(1);
  }

  /* Always discard inputs that time out. */

  if (child_timed_out) {

    exec_hangs++;
    return 0;

  }

  cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

  /* We don't actually care if the target is crashing or not,
     except that when it does, the checksum should be different. */

  cksum ^= 0xffffffff;

  if (first_run) orig_cksum = cksum;

  return cksum;

}


#ifdef USE_COLOR

/* Helper function to display a human-readable character. */

static void show_char(u8 val) {

  if (val <= 32 || val >= 127)
    SAYF("#%02x", val);
  else
    SAYF(" %c ", val);

}


/* Show the legend */

static void show_legend(void) {

  SAYF("    " cLGR bgGRA " 01 " cRST " - no-op block              "
              cBLK bgLGN " 01 " cRST " - suspected length field\n"
       "    " cBRI bgGRA " 01 " cRST " - superficial content      "
              cBLK bgYEL " 01 " cRST " - suspected cksum or magic int\n"
       "    " cBLK bgCYA " 01 " cRST " - critical stream          "
              cBLK bgLRD " 01 " cRST " - suspected checksummed block\n"
       "    " cBLK bgMGN " 01 " cRST " - \"magic value\" section\n\n");

}

#endif /* USE_COLOR */


/* Interpret and report a pattern in the input file. */

static void dump_hex(u8* buf, u32 len, u8* b_data) {

  u32 i;

  for (i = 0; i < len; i++) {

#ifdef USE_COLOR
    u32 rlen = 1, off;
#else
    u32 rlen = 1;
#endif /* ^USE_COLOR */

    u8  rtype = b_data[i] & 0x0f;

    /* Look ahead to determine the length of run. */

    while (i + rlen < len && (b_data[i] >> 7) == (b_data[i + rlen] >> 7)) {

      if (rtype < (b_data[i + rlen] & 0x0f)) rtype = b_data[i + rlen] & 0x0f;
      rlen++;

    }

    /* Try to do some further classification based on length & value. */

    if (rtype == RESP_FIXED) {

      switch (rlen) {

        case 2: {

            u16 val = *(u16*)(in_data + i);

            /* Small integers may be length fields. */

            if (val && (val <= in_len || SWAP16(val) <= in_len)) {
              rtype = RESP_LEN;
              break;
            }

            /* Uniform integers may be checksums. */

            if (val && abs(in_data[i] - in_data[i + 1]) > 32) {
              rtype = RESP_CKSUM;
              break;
            }

            break;

          }

        case 4: {

            u32 val = *(u32*)(in_data + i);

            /* Small integers may be length fields. */

            if (val && (val <= in_len || SWAP32(val) <= in_len)) {
              rtype = RESP_LEN;
              break;
            }

            /* Uniform integers may be checksums. */

            if (val && (in_data[i] >> 7 != in_data[i + 1] >> 7 ||
                in_data[i] >> 7 != in_data[i + 2] >> 7 ||
                in_data[i] >> 7 != in_data[i + 3] >> 7)) {
              rtype = RESP_CKSUM;
              break;
            }

            break;

          }

        default: 
            if (rtype == 1 || rtype == 3 || (rtype >= 5 && rtype <= MAX_AUTO_EXTRA - 1))
                break;
            rtype = RESP_SUSPECT;

      }

    }

    /* Print out the entire run. */

#ifdef USE_COLOR

    for (off = 0; off < rlen; off++) {

      /* Every 16 digits, display offset. */

      if (!((i + off) % 16)) {

        if (off) SAYF(cRST cLCY ">");

        if (use_hex_offsets)
          SAYF(cRST cGRA "%s[%06x] " cRST, (i + off) ? "\n" : "", i + off);
        else
          SAYF(cRST cGRA "%s[%06u] " cRST, (i + off) ? "\n" : "", i + off);

      }

      switch (rtype) {

        case RESP_NONE:     SAYF(cLGR bgGRA); break;
        case RESP_MINOR:    SAYF(cBRI bgGRA); break;
        case RESP_VARIABLE: SAYF(cBLK bgCYA); break;
        case RESP_FIXED:    SAYF(cBLK bgMGN); break;
        case RESP_LEN:      SAYF(cBLK bgLGN); break;
        case RESP_CKSUM:    SAYF(cBLK bgYEL); break;
        case RESP_SUSPECT:  SAYF(cBLK bgLRD); break;

      }

      show_char(in_data[i + off]);

      if (off != rlen - 1 && (i + off + 1) % 16) SAYF(" "); else SAYF(cRST " ");

    }

#else

    if (use_hex_offsets)
      SAYF("    Offset %x, length %u: ", i, rlen);
    else
      SAYF("    Offset %u, length %u: ", i, rlen);

    switch (rtype) {

      case RESP_NONE:     SAYF("no-op block\n"); break;
      case RESP_MINOR:    SAYF("superficial content\n"); break;
      case RESP_VARIABLE: SAYF("critical stream\n"); break;
      case RESP_FIXED:    SAYF("\"magic value\" section\n"); break;
      case RESP_LEN:      SAYF("suspected length field\n"); break;
      case RESP_CKSUM:    SAYF("suspected cksum or magic int\n"); break;
      case RESP_SUSPECT:  SAYF("suspected checksummed block\n"); break;

    }

#endif /* ^USE_COLOR */

    i += rlen - 1;

  }

#ifdef USE_COLOR
  SAYF(cRST "\n");
#endif /* USE_COLOR */

}



/* Actually analyze! */

static void analyze(char** argv) {

  u32 i;
  u32 boring_len = 0, prev_xff = 0, prev_x01 = 0, prev_s10 = 0, prev_a10 = 0;

  u8* b_data = ck_alloc(in_len + 1);
  u8  seq_byte = 0;

  b_data[in_len] = 0xff; /* Intentional terminator. */

  ACTF("Analyzing input file (this may take a while)...\n");

#ifdef USE_COLOR
  show_legend();
#endif /* USE_COLOR */

  for (i = 0; i < in_len; i++) {

    u32 xor_ff, xor_01, sub_10, add_10;
    u8  xff_orig, x01_orig, s10_orig, a10_orig;

    /* Perform walking byte adjustments across the file. We perform four
       operations designed to elicit some response from the underlying
       code. */

    in_data[i] ^= 0xff;
    xor_ff = run_target(argv, in_data, in_len, 0);

    in_data[i] ^= 0xfe;
    xor_01 = run_target(argv, in_data, in_len, 0);

    in_data[i] = (in_data[i] ^ 0x01) - 0x10;
    sub_10 = run_target(argv, in_data, in_len, 0);

    in_data[i] += 0x20;
    add_10 = run_target(argv, in_data, in_len, 0);
    in_data[i] -= 0x10;

    /* Classify current behavior. */

    xff_orig = (xor_ff == orig_cksum);
    x01_orig = (xor_01 == orig_cksum);
    s10_orig = (sub_10 == orig_cksum);
    a10_orig = (add_10 == orig_cksum);

    if (xff_orig && x01_orig && s10_orig && a10_orig) {

      b_data[i] = RESP_NONE;
      boring_len++;

    } else if (xff_orig || x01_orig || s10_orig || a10_orig) {

      b_data[i] = RESP_MINOR;
      boring_len++;

    } else if (xor_ff == xor_01 && xor_ff == sub_10 && xor_ff == add_10) {

      b_data[i] = RESP_FIXED;

    } else b_data[i] = RESP_VARIABLE;

    /* When all checksums change, flip most significant bit of b_data. */

    if (prev_xff != xor_ff && prev_x01 != xor_01 &&
        prev_s10 != sub_10 && prev_a10 != add_10) seq_byte ^= 0x80;

    b_data[i] |= seq_byte;

    prev_xff = xor_ff;
    prev_x01 = xor_01;
    prev_s10 = sub_10;
    prev_a10 = add_10;

  } 

  dump_hex(in_data, in_len, b_data);

  SAYF("\n");

  OKF("Analysis complete. Interesting bits: %0.02f%% of the input file.",
      100.0 - ((double)boring_len * 100) / in_len);

  if (exec_hangs)
    WARNF(cLRD "Encountered %u timeouts - results may be skewed." cRST,
          exec_hangs);

  ck_free(b_data);

}



/* Handle Ctrl-C and the like. */

/*static void handle_stop_sig(int sig) {

  stop_soon = 1;

  if (child_pid > 0) kill(child_pid, SIGKILL);

}*/


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
        prog_in = alloc_printf("%s\\.afl-analyze-temp-%u", use_dir, GetCurrentProcessId());

    }

}

/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {
  //not implemented on Windows
}


/* Detect @@ in args. */

static void detect_file_args(char** argv) {

  u32 i = 0;
  u8* cwd = _getcwd(NULL, 0);

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

      //if (prog_in[0] != '/') ck_free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}


/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s [ options ] -- [instrumentation options] -- \\path\\to\\target_app [ ... ]\n\n"

       "Required parameters:\n\n"

       "  -i file       - input test case to be analyzed by the tool\n"

       "Execution control settings:\n\n"

       "  -f file       - input file read by the tested program (stdin)\n"
       "  -t msec       - timeout for each run (%u ms)\n"
       "  -m megs       - memory limit for child process (%u MB)\n"

       "Analysis settings:\n\n"

       "  -e            - look for edge coverage only, ignore hit counts\n\n"

       "For additional tips, please consult %s/README.\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);

}


/* Find binary. */

static void find_binary(u8* fname) {
  // Not implemented on Windows
}


/* Fix up argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {
  //not implemented on Windows
  return NULL;
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
  u8  mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
  char** use_argv;

  doc_path = "docs";

#ifdef USE_COLOR
  enable_ansi_console();
#endif

  SAYF(cCYA "afl-analyze for Windows " cBRI VERSION cRST " by <l4ys.tw@gmail.com>\n");
  SAYF("Based on WinAFL " cBRI VERSION cRST " by <ifratric@google.com>\n");
  SAYF("Based on AFL " cBRI VERSION cRST " by <lcamtuf@google.com>\n");
  
  while ((opt = getopt(argc,argv,"+i:f:m:t:D:eQY")) > 0)

    switch (opt) {

      case 'D': /* dynamorio dir */

        if(dynamorio_dir) FATAL("Multiple -D options not supported");
        dynamorio_dir = optarg;
        break;

      case 'i':

        if (in_file) FATAL("Multiple -i options not supported");
        in_file = optarg;
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

        }

        break;

      case 't':

        if (timeout_given) FATAL("Multiple -t options not supported");
        timeout_given = 1;

        exec_tmout = atoi(optarg);

        if (exec_tmout < 10 || optarg[0] == '-')
          FATAL("Dangerously low value of -t");

        break;

      case 'Q':

        FATAL("QEMU mode not supported on Windows");
        break;
        
      case 'Y':

        if (dynamorio_dir) FATAL("Dynamic-instrumentation (DRIO) is uncompatible with static-instrumentation");
        drioless = 1;

        break;

      default:

        usage(argv[0]);

    }

  if (!in_file) usage(argv[0]);
  if(!drioless) {
    if(optind == argc || !dynamorio_dir) usage(argv[0]);
  }

  extract_client_params(argc, argv);
  optind++;

  if (getenv("AFL_NO_SINKHOLE")) sinkhole_stds = 0;
  
  use_hex_offsets = !!getenv("AFL_ANALYZE_HEX");

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

  if (!anything_set()) FATAL("No instrumentation detected.");

  analyze(use_argv);

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}
