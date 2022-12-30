#!/bin/zsh


#cmake -G Xcode -Bbuild -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64e


cmake --build build -v -j8 --config Release --target ssl
cmake --build build -v -j8 --config Release --target crypto
cmake --build build -v -j8 --config Release --target decrepit

cmake --build build -v -j8 --config Release --target brotlicommon
cmake --build build -v -j8 --config Release --target brotlidec

cmake --build build -v -j8 --config Release --target cert_decompress
cmake --build build -v -j8 --config Release --target getpeercert

cmake --build build -v -j8 --config Release --target cffi_boringssl
