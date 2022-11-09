cmake_minimum_required(VERSION 3.18)

# if CMAKE_BUILD_TYPE undefined, we set it to Release
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()


project(pyBoringSSL)

add_subdirectory(boringssl)

add_subdirectory(brotli)

add_subdirectory(cert_decompress)

add_subdirectory(getpeercert)
