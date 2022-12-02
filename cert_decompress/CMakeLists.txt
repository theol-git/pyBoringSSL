cmake_minimum_required(VERSION 3.18)
project(cert_decompress)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)

add_library(cert_decompress STATIC cert_decompress.c)

include_directories(../boringssl/include)
include_directories(../brotli/c/include)
include_directories(${CMAKE_BINARY_DIR}/boringssl/symbol_prefix_include)