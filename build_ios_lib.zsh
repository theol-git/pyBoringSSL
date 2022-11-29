#!/bin/zsh


#cmake -G Xcode -Bbuild -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64e


cmake --build build --config Release --target ssl
cmake --build build --config Release --target crypto
cmake --build build --config Release --target decrepit

cmake --build build --config Release --target brotlicommon-static
cmake --build build --config Release --target brotlidec-static

cmake --build build --config Release --target cert_decompress
cmake --build build --config Release --target getpeercert

cmake --build build --config Release --target cffi_boringssl
