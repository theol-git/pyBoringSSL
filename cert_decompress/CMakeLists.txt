cmake_minimum_required(VERSION 3.20)
project(cert_decompress)

# set(CMAKE_CXX_STANDARD 14)

add_library(cert_decompress STATIC cert_decompress.c)

# find_package (Python3 COMPONENTS Interpreter Development)

include_directories(../boringssl/include)
include_directories(../brotli/c/include)