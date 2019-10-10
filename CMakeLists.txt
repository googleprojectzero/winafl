cmake_minimum_required(VERSION 2.6)

if (${USE_COLOR})
    add_definitions(-DUSE_COLOR)
endif()

if (${USE_DRSYMS})
    add_definitions(-DUSE_DRSYMS)
endif()

if (${INTELPT})
    add_definitions(-DINTELPT)
endif()

if (${INTELPT})
  add_subdirectory(third_party/processor-trace)
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

project(afl-fuzz)

SET(AFL_FUZZ_SOURCES afl-fuzz.c)

if (${INTELPT})

  include_directories(third_party/winipt/inc)
  include_directories(third_party/processor-trace/libipt/internal/include)
  include_directories(${CMAKE_CURRENT_BINARY_DIR}/third_party/processor-trace/libipt/include)

  SET(AFL_FUZZ_SOURCES ${AFL_FUZZ_SOURCES} ${PT_ADDITIONAL_SOURCES})

endif()

add_executable(afl-fuzz
  ${AFL_FUZZ_SOURCES}
  )

if (${INTELPT})

  target_link_libraries(afl-fuzz winipt)
  target_link_libraries(afl-fuzz libipt)

  target_link_libraries(afl-fuzz "psapi.lib")
  target_link_libraries(afl-fuzz "Dbghelp.lib")

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
