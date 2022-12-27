## get submodule update:    
    git submodule init  
    git submodule update  


## Requirements:
  ### Android:  
    pkg update  
    pkg install git python build-essential golang  
    pip install cffi   
    
  ### Windows 7(x64):
    conda 3.7-4.8.2 x86_64
    Windows6.1-KB3004394-v2-x64, for update root certificates.
    Virtual Studio (2015 Professional with update 3)
    golang (download and install)
    perl (strawberry-perl is good)
    CMake


  ### Windows:
* Python 3.10 ( or other version you want to build for)    
* Virtual Studio (communication version is good enough)  
* golang (download and install)  
* perl (strawberry-perl is good)  
* CMake

  ### Linux: 
    Python 3.10, (use conda to install)
    apt-get install build-essential 
    golang
  `sudo apt-get install -y libunwind-dev`


## Steps to build and install:  
    python setup.py build install
  You can use x86 python to generate library for x86.
  
  
## Where to get the output lib file:  
    build/lib.$os-$arch-cpython-$version/boring....  
  
  ### Windows:  
    build/lib.win-$arch-cpython-$version/boringssl.pyd  
  To build win32-x86, use python x86 to build, will generate library for x86.
  
  ### Mac:
    build/lib.macosx-10.9-x86_64-cpython-$version/boringssl.abi3.so
  
  ### Android:
    build/lib.linux-aarch64-cpython-$version/boringssl.abi3.so
  
  ### Linux:
    build/lib.linux-x86_64-$version/boringssl.abi3.so
  
## To reduce the lib size:
  `strip boringssl.*` in linux/mac/android
  