## get submodule update:  
git submodule init
git submodule update


## Requirements:
  Android:
    apt install build-essential golang

  Windows: 
    Python 3.10 ( or other version you want to build for)
    Virtual Studio (2019 communication version is good)
    golang (download and install)
    perl (strawberry-perl is good)


## Steps to build and install:  
  python setup.py build install
  
## Where to get the output lib file:
  build/lib.$os-$arch-$python-version/boring....
  
  Windows:
    build/lib.win-amd64-cpython-310/boringssl.pyd
  
  Mac:
    build/lib.macosx-10.9-x86_64-cpython-310/boringssl.abi3.so
  
  Android:
    build/lib.linux-aarch64-cpython-310/boringssl.abi3.so
  
  Linux:
    build/lib.linux-x86_64-3.9/boringssl.abi3.so
  