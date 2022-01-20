/*
   american fuzzy lop - debug / error handling macros
   --------------------------------------------------

   Original AFL code written by Michal Zalewski <lcamtuf@google.com>

   Windows fork written and maintained by Ivan Fratric <ifratric@google.com>

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

#ifndef _HAVE_DEBUG_H
#define _HAVE_DEBUG_H

#include <errno.h>

#include "types.h"
#include "config.h"

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

/*******************
 * Terminal colors *
 *******************/

#ifdef USE_COLOR

#  define cBLK "\x1b[0;30m"
#  define cRED "\x1b[0;31m"
#  define cGRN "\x1b[0;32m"
#  define cBRN "\x1b[0;33m"
#  define cBLU "\x1b[0;34m"
#  define cMGN "\x1b[0;35m"
#  define cCYA "\x1b[0;36m"
#  define cLGR "\x1b[0;37m"
#  define cGRA "\x1b[1;30m"
#  define cLRD "\x1b[1;31m"
#  define cLGN "\x1b[1;32m"
#  define cYEL "\x1b[1;33m"
#  define cLBL "\x1b[1;34m"
#  define cPIN "\x1b[1;35m"
#  define cLCY "\x1b[1;36m"
#  define cBRI "\x1b[1;37m"
#  define cRST "\x1b[0m"

#  define bgBLK "\x1b[40m"
#  define bgRED "\x1b[41m"
#  define bgGRN "\x1b[42m"
#  define bgBRN "\x1b[43m"
#  define bgBLU "\x1b[44m"
#  define bgMGN "\x1b[45m"
#  define bgCYA "\x1b[46m"
#  define bgLGR "\x1b[47m"
#  define bgGRA "\x1b[100m"
#  define bgLRD "\x1b[101m"
#  define bgLGN "\x1b[102m"
#  define bgYEL "\x1b[103m"
#  define bgLBL "\x1b[104m"
#  define bgPIN "\x1b[105m"
#  define bgLCY "\x1b[106m"
#  define bgBRI "\x1b[107m"

#else

#  define cBLK ""
#  define cRED ""
#  define cGRN ""
#  define cBRN ""
#  define cBLU ""
#  define cMGN ""
#  define cCYA ""
#  define cLGR ""
#  define cGRA ""
#  define cLRD ""
#  define cLGN ""
#  define cYEL ""
#  define cLBL ""
#  define cPIN ""
#  define cLCY ""
#  define cBRI ""
#  define cRST ""

#  define bgBLK ""
#  define bgRED ""
#  define bgGRN ""
#  define bgBRN ""
#  define bgBLU ""
#  define bgMGN ""
#  define bgCYA ""
#  define bgLGR ""
#  define bgGRA ""
#  define bgLRD ""
#  define bgLGN ""
#  define bgYEL ""
#  define bgLBL ""
#  define bgPIN ""
#  define bgLCY ""
#  define bgBRI ""

#endif /* ^USE_COLOR */

/*************************
 * Box drawing sequences *
 *************************/

#ifdef FANCY_BOXES

#  define SET_G1   "\x1b)0"       /* Set G1 for box drawing    */
#  define RESET_G1 "\x1b)B"       /* Reset G1 to ASCII         */
#  define bSTART   "\x0e"         /* Enter G1 drawing mode     */
#  define bSTOP    "\x0f"         /* Leave G1 drawing mode     */
#  define bH       "q"            /* Horizontal line           */
#  define bV       "x"            /* Vertical line             */
#  define bLT      "l"            /* Left top corner           */
#  define bRT      "k"            /* Right top corner          */
#  define bLB      "m"            /* Left bottom corner        */
#  define bRB      "j"            /* Right bottom corner       */
#  define bX       "n"            /* Cross                     */
#  define bVR      "t"            /* Vertical, branch right    */
#  define bVL      "u"            /* Vertical, branch left     */
#  define bHT      "v"            /* Horizontal, branch top    */
#  define bHB      "w"            /* Horizontal, branch bottom */

#else

#  define SET_G1   ""
#  define RESET_G1 ""
#  define bSTART   ""
#  define bSTOP    ""
#  define bH       "-"
#  define bV       "|"
#  define bLT      "+"
#  define bRT      "+"
#  define bLB      "+"
#  define bRB      "+"
#  define bX       "+"
#  define bVR      "+"
#  define bVL      "+"
#  define bHT      "+"
#  define bHB      "+"

#endif /* ^FANCY_BOXES */

/***********************
 * Misc terminal codes *
 ***********************/

#ifdef USE_COLOR

#define TERM_HOME     "\x1b[H"
#define TERM_CLEAR    TERM_HOME "\x1b[2J"
#define cEOL          "\x1b[0K"
#define CURSOR_HIDE   "\x1b[?25l"
#define CURSOR_SHOW   "\x1b[?25h"

#else

#define TERM_HOME     ""
#define TERM_CLEAR    ""
#define cEOL          ""
#define CURSOR_HIDE   ""
#define CURSOR_SHOW   ""

#endif /* ^USE_COLORS */

/************************
 * Debug & error macros *
 ************************/

/* Just print stuff to the appropriate stream. */

#ifdef MESSAGES_TO_STDOUT
#  define SAYF(...)    printf(__VA_ARGS__)
#else 
#  define SAYF(...)    fprintf(stderr, __VA_ARGS__)
#endif /* ^MESSAGES_TO_STDOUT */

/* Show a prefixed warning. */

#define WARNF(...) do { \
    SAYF(cYEL "[!] " cBRI "WARNING: " cRST __VA_ARGS__); \
    SAYF(cRST "\n"); \
  } while (0)

/* Show a prefixed "doing something" message. */

#define ACTF(...) do { \
    SAYF(cLBL "[*] " cRST __VA_ARGS__); \
    SAYF(cRST "\n"); \
  } while (0)

/* Show a prefixed "success" message. */

#define OKF(...) do { \
    SAYF(cLGN "[+] " cRST __VA_ARGS__); \
    SAYF(cRST "\n"); \
  } while (0)

/* Show a prefixed fatal error message (not used in afl). */

#define BADF(...) do { \
    SAYF(cLRD "\n[-] " cRST __VA_ARGS__); \
    SAYF(cRST "\n"); \
  } while (0)

/* Die with a verbose non-OS fatal error message. */

#define FATAL(...) do { \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cLRD "\n[-] PROGRAM ABORT : " cBRI __VA_ARGS__); \
    SAYF(cLRD "\n         Location : " cRST "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    exit(1); \
  } while (0)

/* Die by calling abort() to provide a core dump. */

#define ABORT(...) do { \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cLRD "\n[-] PROGRAM ABORT : " cBRI __VA_ARGS__); \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    abort(); \
  } while (0)

/* Die while also including the output of perror(). */

#define PFATAL(...) do { \
    fflush(stdout); \
    SAYF(bSTOP RESET_G1 CURSOR_SHOW cLRD "\n[-]  SYSTEM ERROR : " cBRI __VA_ARGS__); \
    SAYF(cLRD "\n    Stop location : " cRST "%s(), %s:%u\n", \
         __FUNCTION__, __FILE__, __LINE__); \
    SAYF(cLRD "       OS message : " cRST "%s\n", strerror(errno)); \
    exit(1); \
  } while (0)

/* Die with FAULT() or PFAULT() depending on the value of res (used to
   interpret different failure modes for read(), write(), etc). */

#define RPFATAL(res, ...) do { \
    if (res < 0) PFATAL(__VA_ARGS__); else FATAL(__VA_ARGS__); \
  } while (0)

/* Error-checking versions of read() and write() that call RPFATAL() as
   appropriate. */

#define ck_write(fd, buf, len, fn) do { \
    u32 _len = (len); \
    s32 _res = _write(fd, buf, _len); \
    if (_res != _len) RPFATAL(_res, "Short write to %s", fn); \
  } while (0)

#define ck_read(fd, buf, len, fn) do { \
    u32 _len = (len); \
    s32 _res = _read(fd, buf, _len); \
    if (_res != _len) RPFATAL(_res, "Short read from %s", fn); \
  } while (0)


static void enable_ansi_console(void) {
  // Set output mode to handle virtual terminal sequences
  DWORD mode = 0;
  HANDLE console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
  if (console_handle == INVALID_HANDLE_VALUE) {
    return;
  }

  if (!GetConsoleMode(console_handle, &mode)) {
    return;
  }

  mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
  // Ignore errors
  SetConsoleMode(console_handle, mode);
}


#endif /* ! _HAVE_DEBUG_H */
