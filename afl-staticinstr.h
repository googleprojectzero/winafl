/*
   WinAFL persistent loop implementation for statically instrumented target
   -----------------------------------------------------------------------

   Written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This header is the glue you need to make afl-fuzz and your statically
   instrumented target play nice together.

   The entry-point __afl_persistent_loop is meant to be called at the start of the harness,
   in a loop like below. The function will set up everything needed to communicate
   and synchronize with afl-fuzz - if it is present (named pipe, shm, etc).

      while(__afl_persistent_loop()) {
          // init state
          // exercise target
          // clear state
      }

   If afl-fuzz isn't detected, then the function will simply return TRUE the first
   time so that the body gets executed once.
*/
#pragma once
#include <Windows.h>
#include <stdint.h>
#include <tchar.h>

#if defined(_M_X64) || defined(__amd64__)
#error Static instrumentation is only available for 32 bit binaries
#endif

//
// Enable the variable behavior debugging mode.
//

// #define AFL_STATIC_VARIABLE_BEHAVIOR_DEBUG

#ifdef __cplusplus
extern "C" {
#endif

BOOL __afl_persistent_loop();

#ifdef __cplusplus
}
#endif
