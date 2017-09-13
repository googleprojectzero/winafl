cmake_minimum_required(VERSION 2.6)


project(test)

add_executable(test
  test.cpp
  )

if(NOT "${CMAKE_GENERATOR}" MATCHES "(Win64)")

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

project(afl-showmap)

add_executable(afl-showmap
  afl-showmap.c
  )

project(afl-fuzz)

add_executable(afl-fuzz
  afl-fuzz.c
  )

project(afl-tmin)

add_executable(afl-tmin
  afl-tmin.c
  )


project(WinAFL)

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
use_DynamoRIO_extension(winafl drsyms)

# VS2015 Fix
if (NOT (MSVC_VERSION LESS 1900))
  target_link_libraries(winafl "libucrt.lib")
  target_link_libraries(winafl "libvcruntime.lib")
endif()

