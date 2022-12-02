cmake_minimum_required(VERSION 3.18)
project(getpeercert)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)


find_package (Python3 COMPONENTS Interpreter Development)

include_directories(../boringssl/include)
include_directories(${CMAKE_BINARY_DIR}/boringssl/symbol_prefix_include)
include_directories(${Python3_INCLUDE_DIRS})
add_library(getpeercert STATIC x509_getpeercert.c)
