#!/bin/bash



cd brotli
rm -rf out
mkdir out
cd out
cmake ..
make -j


cd ../..

cd boringssl
rm -rf build
mkdir build
cd build
cmake ..
make -j
mv ssl/libssl.a ssl/libbssl.a
mv crypto/libcrypto.a crypto/libbcrypto.a
