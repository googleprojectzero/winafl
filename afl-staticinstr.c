/*
   WinAFL persistent loop implementation for statically instrumented target
   -----------------------------------------------------------------------

   Written by Axel "0vercl0k" Souchet <0vercl0k@tuxfamily.org>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0
*/
#include "afl-staticinstr.h"
#include <stdio.h>
#include <psapi.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAP_SIZE 65536
#define STATIC_COV_SECTION_NAME ".syzyafl"
#define STATIC_COV_SECTION_NAME_LEN 8
#define AFL_STATIC_CONFIG_ENV TEXT("AFL_STATIC_CONFIG")
#define AFL_VARIABLE_BEHAVIOR_TRACES_BASE_DIR TEXT("C:\\traces")
#define AFL_VARIABLE_BEHAVIOR_ITERATIONS 10
#define MAX_STRING_SIZE 64

#pragma pack(push, 1)
typedef struct {
    UINT32 __tls_index;
    UINT32 __tls_slot_offset;
    PUINT32 __afl_prev_loc;
    PUCHAR __afl_area_ptr;
    CHAR __afl_area[MAP_SIZE];
} STATIC_COVERAGE_DATA, *PSTATIC_COVERAGE_DATA;
#pragma pack(pop)

//
// The handle to the pipe used to talk with afl-fuzz.exe
//

HANDLE g_winafl_pipe = INVALID_HANDLE_VALUE;

//
// The no fuzzing mode is enabled when a binary is run without
// passing the fuzzing configuration in the AFL_STATIC_CONFIG
// environment variable (running a binary by itself, without
// being run via afl-fuzz.exe will enable this mode for example).
// Under this mode, the persistent loop exits after a single
// iteration.
//

BOOL g_nofuzzing_mode = FALSE;

//
// The no instrumentation mode means the binary is running
// without an AFL instrumented module in its address-space.
// As a result, it means there is no coverage information
// available (g_static_coverage_data is empty). This happens
// when the persistent loop is run without instrumenting any
// modules.
//

BOOL g_noinstrumentation = TRUE;

//
// The number of instrumented modules available in the
// address space.
//

SIZE_T g_ninstrumented_modules = 0;

//
// The coverage data is a pointer to a structure that
// can be found in an instrumented binary, in its '.syzyafl'
// section. A pointer to the coverage map can be found in it,
// but also what type of instrumentation it is using (single/multi thread).
// Note that, it is NULL when g_noinstrumentation is TRUE.

#define kMaximumInstrumentedModules 10
STATIC_COVERAGE_DATA *g_static_coverage_data[kMaximumInstrumentedModules];

//
// The current iterations track the number of iterations the persistent
// loop has been through.
//

SIZE_T g_current_iterations = 0;

//
// The n iterations is the total number total iterations that
// afl-fuzz.exe wants to be run every time the target process is
// spawned. This is configured via the AFL_STATIC_CONFIG environment
// variable.
//

SIZE_T g_niterations = 0;

//
// Some synchronization primitives.
//

CRITICAL_SECTION g_crit_section;
INIT_ONCE g_init_once = INIT_ONCE_STATIC_INIT, g_init_once_bareminimum = INIT_ONCE_STATIC_INIT;

LONG CALLBACK __afl_VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)

/*++

Routine Description:

    Catch exceptions and let afl-fuzz.exe know when an interesting
    one happened.

Arguments:

    ExceptionInfo - A structure with information about the exception
    that triggered the invocation of the vectored exception handler.

Return Value:

    EXCEPTION_CONTINUE_SEARCH if exception not handled.

--*/


{
    DWORD Dummy;
    EnterCriticalSection(&g_crit_section);

    if(
        ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C
#ifdef DBG_PRINTEXCEPTION_WIDE_C

        //
        // This define has been introduced in the Windows 10 SDK and doesn't
        // exist in older SDKs.
        //

        || ExceptionInfo->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_WIDE_C
#endif
    ) {
        _tprintf(TEXT("[*] Received an OutputDebugString exception.\n"));
    }
    else if(ExceptionInfo->ExceptionRecord->ExceptionCode == 0xE06D7363) {

        //
        // https://support.microsoft.com/fr-fr/help/185294/prb-exception-code-0xe06d7363-when-calling-win32-seh-apis
        // https://blogs.msdn.microsoft.com/oldnewthing/20100730-00/?p=13273
        //

        _tprintf(TEXT("[*] Received an MSVC C++ exception.\n"));
    }
    else {
        _tprintf(TEXT("[*] The program just crashed.\n"));
        if(g_nofuzzing_mode == FALSE) {
            WriteFile(g_winafl_pipe, "C", 1, &Dummy, NULL);
            TerminateProcess(GetCurrentProcess(), 0);
        }
    }

    LeaveCriticalSection(&g_crit_section);
    _tprintf(TEXT("[+] Passing it to the program (might trigger a JIT debugger if it can't handle it).\n"));
    return EXCEPTION_CONTINUE_SEARCH;
}

VOID __afl_display_banner()

/*++

Routine Description:

    Displays the AFL persistent loop banner.

Arguments:

    None.

Return Value:

    None.

--*/

{
    _tprintf(TEXT("Persistent loop implementation by <0vercl0k@tuxfamily.org>\n"));
    _tprintf(TEXT("Based on WinAFL by <ifratric@google.com>\n"));
}

BOOL CALLBACK __afl_set_it_up(
    PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context
)

/*++

Routine Description:

    Sets up the environment: creates the pipe to talk with afl-fuzz.exe,
    maps the coverage byte-map that afl-fuzz.exe will map in and fix-up
    the instrumented module so that its coverage byte-map pointer points
    inside the shared memory section.

Arguments:

    InitOnce - Unused.

    Parameter - Unused.

    Context - Unused.

Return Value:

    TRUE on success, FALSE otherwise.

--*/

{
    BOOL Status = TRUE;
    HANDLE MappedFile = NULL;
    PVOID AreaPtr = NULL;
    DWORD SizeNeeded;
    HMODULE Modules[128];
    SIZE_T i = 0;
    TCHAR PipeName[MAX_STRING_SIZE], ShmName[MAX_STRING_SIZE],
          FuzzerId[MAX_STRING_SIZE], StaticConfig[MAX_STRING_SIZE],
          InstrumentedModuleName[MAX_STRING_SIZE];

    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    EnterCriticalSection(&g_crit_section);

    //
    // Let's first figure out if we are running with any instrumented module,
    // in the address space.
    // If not, we turn on the no instrumentation switch.
    //

    Status = EnumProcessModulesEx(GetCurrentProcess(), Modules, sizeof(Modules), &SizeNeeded, LIST_MODULES_32BIT);

    if(Status == FALSE) {
        _tprintf(TEXT("[-] EnumProcessModulesEx failed - too many modules loaded?.\n"));
        TerminateProcess(GetCurrentProcess(), 0);
    }

    for(i = 0; i < SizeNeeded / sizeof(Modules[0]); ++i) {
        PVOID Base = (PVOID)Modules[i];
        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
        PIMAGE_SECTION_HEADER Sections = (PIMAGE_SECTION_HEADER)(NtHeaders + 1);
        USHORT j = 0;

        for(j = 0; j < NtHeaders->FileHeader.NumberOfSections; ++j) {
            if(memcmp(Sections[j].Name, STATIC_COV_SECTION_NAME, STATIC_COV_SECTION_NAME_LEN) != 0) {
                continue;
            }

            //
            // Make sure we haven't exhausted the number of slots for the static coverage
            // information.
            //

            if(g_ninstrumented_modules == ARRAYSIZE(g_static_coverage_data)) {
                _tprintf(
                    TEXT("[!] You have exhausted the number of instrumented modules (%d).\n"),
                    g_ninstrumented_modules
                );
                break;
            }

            GetModuleBaseName(GetCurrentProcess(), Modules[i], InstrumentedModuleName, MAX_STRING_SIZE);
            g_static_coverage_data[g_ninstrumented_modules] = (STATIC_COVERAGE_DATA*)(
                Sections[j].VirtualAddress + (DWORD)Base
            );

            _tprintf(
                TEXT("[+] Found a statically instrumented module: %s (%s thread mode).\n"),
                InstrumentedModuleName,
                (g_static_coverage_data[g_ninstrumented_modules]->__tls_slot_offset == 0) ?
                TEXT("single") : TEXT("multi")
            );
            g_ninstrumented_modules++;
            g_noinstrumentation = FALSE;
            break;
        }
    }

    if(g_noinstrumentation == TRUE) {
        _tprintf(TEXT("[-] No instrumented module found.\n"));
        Status = FALSE;
    }

    //
    // Let's figure out, if afl-fuzz.exe spawned us or not?
    // If not, we can switch on the no fuzzing mode and exit.
    //

    if(GetEnvironmentVariable(AFL_STATIC_CONFIG_ENV, StaticConfig, MAX_STRING_SIZE) == 0) {
        _tprintf(TEXT("[-] Not running under afl-fuzz.exe.\n"));
        g_nofuzzing_mode = TRUE;
        Status = FALSE;
        goto clean;
    }

    //
    // We are running under afl-fuzz.exe; let's open the pipe used for
    // communication, create a named shared memory section to store the coverage
    // data and fix-up the instrumented module so that its instrumentation writes
    // in the shared memory section's content.
    //

    memset(PipeName, 0, MAX_STRING_SIZE * sizeof(PipeName[0]));
    memset(ShmName, 0, MAX_STRING_SIZE * sizeof(ShmName[0]));

    _tprintf(TEXT("[*] Setting up the environment (%s)..\n"), StaticConfig);
    if(_stscanf_s(StaticConfig, TEXT("%[a-zA-Z0-9]:%u"), FuzzerId, _countof(FuzzerId), &g_niterations) != 2) {
        _tprintf(
            TEXT("[-] The ") AFL_STATIC_CONFIG_ENV TEXT(" environment variable isn't properly formated.\n")
        );
        Status = FALSE;
        goto clean;
    }

    _stprintf_s(PipeName, _countof(PipeName), TEXT("\\\\.\\pipe\\afl_pipe_%s"), FuzzerId);
    _stprintf_s(ShmName, _countof(ShmName), TEXT("afl_shm_%s"), FuzzerId);

    //
    // Connect to the named pipe.
    //

    g_winafl_pipe = CreateFile(
        PipeName,                      // pipe name
        GENERIC_READ | GENERIC_WRITE,  // read and write access
        0,                             // no sharing
        NULL,                          // default security attributes
        OPEN_EXISTING,                 // opens existing pipe
        0,                             // default attributes
        NULL                           // no template file
    );

    if(g_winafl_pipe == INVALID_HANDLE_VALUE) {
        _tprintf(TEXT("[-] Opening the named pipe failed.\n"));
        Status = FALSE;
        goto clean;
    }

    //
    // Get the named shared memory section mapped.
    //

    MappedFile = OpenFileMapping(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        ShmName
    );

    if(MappedFile == NULL) {
        _tprintf(TEXT("[-] Opening the file mapping failed.\n"));
        Status = FALSE;
        goto clean;
    }

    AreaPtr = MapViewOfFile(
        MappedFile,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        MAP_SIZE
    );

    if(AreaPtr == NULL) {
        _tprintf(TEXT("[-] Mapping a view of the shared memory section failed.\n"));
        Status = FALSE;
        goto clean;
    }

    //
    // Fix up the instrumented modules so that the pointer storing the base
    // of the coverage map points to the shared memory section we just mapped in.
    // The instrumented code will now write the coverage information directly
    // in the shared section.
    //

    for(i = 0; i < g_ninstrumented_modules; ++i) {
        g_static_coverage_data[i]->__afl_area_ptr = (PUCHAR)AreaPtr;
    }

    _tprintf(TEXT("[+] Fixed-up the %d instrumented modules.\n"), g_ninstrumented_modules);

    clean:

    if(g_nofuzzing_mode == FALSE && g_noinstrumentation == TRUE) {

        //
        // It means there is no instrumented module in the address space,
        // and we are being run through AFL..weird. Display a pop-up!
        //

        _tprintf(TEXT("[-] You are running without instrumentation under afl-fuzz.exe.\n"));

        MessageBox(
            NULL,
            TEXT("You are running without instrumentation under afl-fuzz.exe."),
            NULL,
            MB_OK | MB_ICONERROR
        );
    }

    if(MappedFile != NULL) {
        CloseHandle(MappedFile);
    }

    LeaveCriticalSection(&g_crit_section);
    return Status;
}

BOOL CALLBACK __afl_set_up_bareminimum(
    PINIT_ONCE InitOnce, PVOID Parameter, PVOID *Context
)

/*++

Routine Description:

    Installs the vectored exception handler to ease reproducability.
    The VEH gets installed even if running without afl-fuzz.exe, or
    if running a non-instrumented module. This is particularly useful
    for debugging issues found by afl-fuzz.exe on a vanilla target (in
    the case the debugging symbols are a bit funky on an instrumented
    binary for example). Also initialize the critical section.

Arguments:

    InitOnce - Unused.

    Parameter - Unused.

    Context - Unused.

Return Value:

    TRUE.

--*/

{
    UNREFERENCED_PARAMETER(InitOnce);
    UNREFERENCED_PARAMETER(Parameter);
    UNREFERENCED_PARAMETER(Context);

    InitializeCriticalSection(&g_crit_section);

    //
    // Set up the exception handler.
    //

    AddVectoredExceptionHandler(0, __afl_VectoredHandler);

    //
    // Display the banner to know the persistent loop is here.
    //

    __afl_display_banner();
    return TRUE;
}

BOOL __afl_persistent_loop()

/*++

Routine Description:

    Persistent loop implementation.

Arguments:

    None.

Return Value:

    TRUE until the iteration count gets hit, and then FALSE.

--*/

{
    BOOL Status;
    CHAR Command = 0;
    DWORD Dummy;
    SIZE_T i = 0;

    if(g_nofuzzing_mode == TRUE) {

        //
        // Force exit at the first iteration when afl-fuzz isn't detected
        // to fake "normal" execution of instrumented binary.
        //

        Status = FALSE;
        goto clean;
    }

    Status = InitOnceExecuteOnce(
        &g_init_once_bareminimum,
        __afl_set_up_bareminimum,
        NULL,
        NULL
    );

    Status = InitOnceExecuteOnce(
        &g_init_once,
        __afl_set_it_up,
        NULL,
        NULL
    );

    if(Status == FALSE) {
        _tprintf(TEXT("[+] Enabling the no fuzzing mode.\n"));
        g_nofuzzing_mode = TRUE;
        Status = TRUE;
        goto clean;
    }

    //
    // If this not the first time, it means we have to signal afl-fuzz that
    // the previous test-case ended.
    //

    if(g_current_iterations > 0) {
        WriteFile(g_winafl_pipe, "K", 1, &Dummy, NULL);
    }

    if(g_current_iterations == g_niterations) {

        //
        // It is time to stop the machine!
        //

        CloseHandle(g_winafl_pipe);
        g_winafl_pipe = INVALID_HANDLE_VALUE;

        UnmapViewOfFile(g_static_coverage_data[0]->__afl_area_ptr);

        //
        // Redirect the coverage map back into the instrumented binary's
        // .syzyafl section so that the program doesn't crash while exiting.
        //

        for(i = 0; i < g_ninstrumented_modules; ++i) {
            g_static_coverage_data[i]->__afl_area_ptr = (PUCHAR)g_static_coverage_data[i]->__afl_area;
        }

        Status = FALSE;
        goto clean;
    }

    //
    // Tell afl-fuzz that we are ready for the next iteration.
    //

    WriteFile(g_winafl_pipe, "P", 1, &Dummy, NULL);

    //
    // Wait until we have the go from afl-fuzz to go ahead (below call is blocking).
    //

    ReadFile(g_winafl_pipe, &Command, 1, &Dummy, NULL);
    if(Command != 'F') {
        if(Command == 'Q') {
            _tprintf(TEXT("[+] Received the quit signal, exiting.\n"));
        } else {
            _tprintf(TEXT("[-] Received an unknown command from afl-fuzz, exiting (%.2x).\n"), Command);
        }

        TerminateProcess(GetCurrentProcess(), 0);
    }

    clean:

    g_current_iterations++;

#ifdef AFL_STATIC_VARIABLE_BEHAVIOR_DEBUG

    {
        //
        // To ease debugging of variable behavior, we fake a configuration
        // where we run 10 iterations through the persistent loop, and
        // we save to disk the coverage map at every iterations.
        // You can then diff them and understand what parts of the map
        // get changed, and you can then set hardware write access breakpoints
        // to see what is the code writing in the coverage map.
        //

        FILE *CoverageFile = NULL;
        TCHAR CoverageFilename[MAX_STRING_SIZE];

        if(g_current_iterations == 1) {

            //
            // Check various things on the first iteration. This is the
            // only time this block will get executed.
            //

            //
            // We cannot run in this mode if no instrumentation has been found, as
            // there won't be any coverage map.
            //

            if(g_noinstrumentation == TRUE) {
                _tprintf(TEXT(
                    "[-] Cannot run the variable behavior debugging mode without an instrumented module.\n"
                ));
                Status = FALSE;
                goto end;
            }

            //
            // We cannot run in this mode if we are fuzzing right now, display a message
            // box as - most likely - afl-fuzz.exe is sink-holing stdout messages.
            //

            if(g_nofuzzing_mode == FALSE) {
                MessageBox(
                    NULL,
                    TEXT("You are running the target under afl-fuzz.exe with the variable behavior debugging mode."),
                    NULL,
                    MB_OK | MB_ICONERROR
                );
                Status = FALSE;
                goto end;
            }

            //
            // Let the user knows that the variable behavior debugging mode is enabled,
            // and configure the number of iterations.
            //

            _tprintf(TEXT("[+] Enabled the variable behavior debugging mode.\n"));
            g_niterations = AFL_VARIABLE_BEHAVIOR_ITERATIONS;

            //
            // Fix-up all the coverage maps to point into the first one's.
            //

            for(i = 1; i < g_ninstrumented_modules; ++i) {
                g_static_coverage_data[i]->__afl_area_ptr = (PUCHAR)g_static_coverage_data[0]->__afl_area;
            }

            if(IsDebuggerPresent()) {

                //
                // If we are under a debugger, let's give to the user the
                // coverage map base address as it is useful to break on write
                // access to certain bytes in the map to investigate variable
                // behaviors test-cases.
                //

                _tprintf(
                    TEXT("[+] Coverage map base: %p.\n"),
                    g_static_coverage_data[0]->__afl_area_ptr
                );

                //
                // Also breaking so that the user can set its breakpoints before
                // we start running the persistent loop.
                //

                __debugbreak();
            }
        }

        //
        // Force the persistent loop to run again if we need it to.
        //

        if(g_current_iterations == g_niterations) {

            //
            // We are done!
            //

            Status = FALSE;
        } else {

            //
            // Force re-entering the persistent loop again.
            //

            g_nofuzzing_mode = FALSE;
        }

        if(g_current_iterations > 1 && !IsDebuggerPresent()) {

            //
            // Write the coverage map to disk if this is not the first
            // iteration as the instrumented code didn't get a chance
            // to be executed yet. We also don't overwrite the traces if a
            // debugger is attached, as it most likely means that an
            // investigation is on-going.
            //

            _stprintf_s(
                CoverageFilename, _countof(CoverageFilename),
                AFL_VARIABLE_BEHAVIOR_TRACES_BASE_DIR "\\%u.bin", g_current_iterations - 1
            );

            if(_tfopen_s(&CoverageFile, CoverageFilename, TEXT("wb"))) {
                _tprintf(TEXT("[-] Cannot open %s.\n"), CoverageFilename);
            } else {
                fwrite(g_static_coverage_data[0]->__afl_area_ptr, MAP_SIZE, 1, CoverageFile);
                fclose(CoverageFile);
            }
        }
    }

    end:

#endif

    if(g_noinstrumentation == FALSE) {

        //
        // Reset the global state only if we have found an instrumented
        // module earlier - otherwise the g_static_coverage_data array
        // is empty.
        //

        for(i = 0; i < g_ninstrumented_modules; ++i) {
            PUINT32 PerThreadPrevLoc;
            STATIC_COVERAGE_DATA *CurrentCoverageData = g_static_coverage_data[i];
            if(CurrentCoverageData->__tls_slot_offset != 0) {

                //
                // TLS version if we are fuzzing a multithread instrumented binary.
                //

                PUINT32 Base = (PUINT32)(__readfsdword(0x2C) + (4 * CurrentCoverageData->__tls_index));
                PerThreadPrevLoc = (PUINT32)(*Base + CurrentCoverageData->__tls_slot_offset);
            } else {
                PerThreadPrevLoc = (PUINT32)(&CurrentCoverageData->__afl_prev_loc);
            }

            *PerThreadPrevLoc = 0;
        }

        memset(g_static_coverage_data[0]->__afl_area_ptr, 0, MAP_SIZE);
    }

#ifdef AFL_STATIC_VARIABLE_BEHAVIOR_DEBUG

    //
    // Make sure to reinitialize the counter to 0 in order
    // to not exhaust all the slots.
    //

    g_ninstrumented_modules = 0;

#endif

    return Status;
}

#ifdef __cplusplus
}
#endif
