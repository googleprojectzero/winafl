cmake_minimum_required(VERSION 3.18) # Upgrade for CMAKE_CUDA_ARCHITECTURES

project(WinAFL_CUDA LANGUAGES C CXX)
set(CMAKE_CUDA_ARCHITECTURES native)

# CUDA Support - Contributed by Elias Ibrahim <elie.ibrahim@gmail.com> (Feb 2026)
enable_language(CUDA)

# Check if CUDA is found (enable_language should handle this, but explicit check is good)
if(NOT CMAKE_CUDA_COMPILER)
    message(WARNING "CUDA compiler not found! GPU acceleration will be disabled.")
else()
    message(STATUS "CUDA compiler found: ${CMAKE_CUDA_COMPILER}")
    add_definitions(-DHAVE_CUDA)
endif()

if (${USE_COLOR})
    add_definitions(-DUSE_COLOR)
endif()

if (${USE_DRSYMS})
    add_definitions(-DUSE_DRSYMS)
endif()

if (${INTELPT})
    add_definitions(-DINTELPT)
endif()

# CUDA Support
# CUDA Support - Handled by enable_language(CUDA)
if (CMAKE_CUDA_COMPILER)
    add_definitions(-DHAVE_CUDA)
    include_directories(${CMAKE_CUDA_TOOLKIT_INCLUDE_DIRECTORIES})
else()
    message(WARNING "CUDA not found, GPU acceleration will be disabled.")
endif()

if (${INTELPT})
  add_subdirectory(third_party/processor-trace)
endif()

if (${TINYINST})
    add_definitions(-DTINYINST)
endif()

if (${TINYINST})
  add_subdirectory(third_party/TinyInst)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

project(test)

add_executable(test
  test.cpp
  )

project(test_netmode)

add_executable(test_netmode test_netmode.cpp)

add_executable(test_servermode test_simple_winsock_client.cpp)

if(NOT ("${CMAKE_GENERATOR}" MATCHES "(Win64)" OR "${CMAKE_GENERATOR_PLATFORM}" MATCHES "(64)"))

  project(test_static)

  add_executable(test_static
    test_static.cpp
    afl-staticinstr.c
    )

  target_link_libraries(test_static "psapi.lib")

  set_target_properties(test_static PROPERTIES COMPILE_FLAGS "/EHsc")
  set_target_properties(test_static PROPERTIES LINK_FLAGS "/PROFILE")

endif()

project(test_gdiplus)

add_executable(test_gdiplus
  gdiplus.cpp
  )

target_link_libraries(test_gdiplus gdiplus)

project(afl-analyze)
add_executable(afl-analyze
  afl-analyze.c
  )

project(afl-showmap)

add_executable(afl-showmap
  afl-showmap.c
  )

project(afl-tmin)

add_executable(afl-tmin
  afl-tmin.c
  )

add_library(custom_winafl_server SHARED custom_winafl_server.c custom_winafl_server.def)

add_library(custom_net_fuzzer SHARED custom_net_fuzzer.c custom_net_fuzzer.def)

if (${INTELPT})

  project(winipt)

  include_directories(third_party/winipt/inc)

  ADD_LIBRARY(winipt STATIC
    ipttool.c
    third_party/winipt/libipt/win32.c
    )

  target_compile_definitions(winipt PRIVATE UNICODE _UNICODE)

  project(winaflpt-debug)

  include_directories(third_party/winipt/inc)
  include_directories(third_party/processor-trace/libipt/internal/include)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/processor-trace/libipt/include)

  SET(PT_ADDITIONAL_SOURCES
    winaflpt.c
    ptdecode.c
    third_party/processor-trace/libipt/src/pt_cpu.c
    third_party/processor-trace/libipt/src/windows/pt_cpuid.c
    )

  ADD_EXECUTABLE(winaflpt-debug
    winaflpt-debug.c
    ${PT_ADDITIONAL_SOURCES}
    )

  target_link_libraries(winaflpt-debug winipt)
  target_link_libraries(winaflpt-debug libipt)

  target_link_libraries(winaflpt-debug "psapi.lib")
  target_link_libraries(winaflpt-debug "Dbghelp.lib")

endif()

if (${TINYINST})
  ADD_LIBRARY(winafl_tinyinst STATIC
    tinyinst_covmap.h
    tinyinst_covmap.cpp
    tinyinst_afl.h
    tinyinst_afl.cpp
    )

  target_link_libraries(winafl_tinyinst tinyinst)
  target_link_libraries(winafl_tinyinst "onecore.lib")

endif()


project(afl-fuzz)

SET(AFL_FUZZ_SOURCES afl-fuzz.c)

if(CMAKE_CUDA_COMPILER)
    SET(AFL_FUZZ_SOURCES ${AFL_FUZZ_SOURCES} afl-fuzz-gpu.cu)
endif()

if(DEFINED GPU_SANDBOX_DIR)
    add_subdirectory(${GPU_SANDBOX_DIR} gpu_sandbox_build)
    include_directories(${GPU_SANDBOX_DIR}/include)
    add_definitions(-DUSE_GPU_SANDBOX)
endif()

if (${INTELPT})

  include_directories(third_party/winipt/inc)
  include_directories(third_party/processor-trace/libipt/internal/include)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/processor-trace/libipt/include)

  SET(AFL_FUZZ_SOURCES ${AFL_FUZZ_SOURCES} ${PT_ADDITIONAL_SOURCES})

endif()

add_executable(afl-fuzz
  ${AFL_FUZZ_SOURCES}
  )

if(DEFINED GPU_SANDBOX_DIR)
    target_link_libraries(afl-fuzz gpu_sandbox)
endif()

# if (CMAKE_CUDA_COMPILER)
#   Target linking is automatic for CUDA sources
# endif()

if (${INTELPT})

  target_link_libraries(afl-fuzz winipt)
  target_link_libraries(afl-fuzz libipt)

  target_link_libraries(afl-fuzz "psapi.lib")
  target_link_libraries(afl-fuzz "Dbghelp.lib")

endif()

if (${TINYINST})
  target_link_libraries(afl-fuzz winafl_tinyinst)
endif()

if (NOT "${DynamoRIO_DIR}" STREQUAL "")

  project(WinAFL)

  set(DynamoRIO_LOG_COMPATIBILITY on)

  find_package(DynamoRIO)
  if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
  endif(NOT DynamoRIO_FOUND)

  if (STATIC_LIBRARY)
    set(libtype STATIC)
  else()
    set(libtype SHARED)
  endif ()

  add_library(winafl ${libtype}
    winafl.c
    modules.c
    )
  configure_DynamoRIO_client(winafl)
  use_DynamoRIO_extension(winafl drmgr)
  use_DynamoRIO_extension(winafl drx)
  use_DynamoRIO_extension(winafl drcontainers)
  use_DynamoRIO_extension(winafl drreg)
  use_DynamoRIO_extension(winafl drwrap)
  if (${USE_DRSYMS})
    use_DynamoRIO_extension(winafl drsyms)
  endif()

  # VS2015 Fix
  if (NOT (MSVC_VERSION LESS 1900))
    target_link_libraries(winafl "libucrt.lib")
    target_link_libraries(winafl "libvcruntime.lib")
  endif()

endif()
