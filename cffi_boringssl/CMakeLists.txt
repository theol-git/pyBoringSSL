cmake_minimum_required(VERSION 3.18)
project(cffi_boringssl)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

add_library(cffi_boringssl STATIC boringssl.c)

find_package (Python3 COMPONENTS Interpreter Development)

include_directories(../boringssl/include)
include_directories(../brotli/c)
include_directories(../brotli/c/include)
include_directories(${Python3_INCLUDE_DIRS})
