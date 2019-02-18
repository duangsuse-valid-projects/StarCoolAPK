cmake_minimum_required(VERSION 3.0.2)

project(reliba)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99 -O3 -fno-stack-protector")

set(A_SOURCE_FILES coolapk.c)
set(B_SOURCE_FILES base64.c)
set(M_SOURCE_FILES md5.c)

set(inc "include/")

set(A_HEADERS "${inc}coolapk.h")
set(B_HEADERS "${inc}base64.h")
set(M_HEADERS "${inc}md5_digest.h")

set(BUILD_USE_64BITS on)

add_library(
  base64
  ${B_SOURCE_FILES}
  ${B_HEADERS}
)

add_library(
  md5
  ${M_SOURCE_FILES}
  ${M_HEADERS}
)

add_library(
  coolapk
  ${A_SOURCE_FILES}
  ${A_HEADERS}
)

# Shared libraries

add_library(
  a SHARED
  ${A_SOURCE_FILES}
  ${A_HEADERS}
  md5
  base64
)

target_link_libraries(a base64 md5)

# Test executables

add_executable(
  test
  main.c
  coolapk
  md5
  base64
)

add_executable(test32 main.c coolapk md5 base64)
set_target_properties(test32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")

