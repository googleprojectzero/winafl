cmake_minimum_required(VERSION 2.6)


project(test)

add_executable(test
  test.cpp
  )


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

