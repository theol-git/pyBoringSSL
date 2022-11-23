## get submodule update:    
    git submodule init  
    git submodule update  


## Requirements:
  ### Android:  
    pkg update  
    pkg install git python build-essential golang  
    pip install cffi   
    

  ### Windows:
* Python 3.10 ( or other version you want to build for)    
* Virtual Studio (communication version is good enough)  
* golang (download and install)  
* perl (strawberry-perl is good)  


## Steps to build and install:  
    python setup.py build install
  You can use x86 python to generate library for x86.
  
## Where to get the output lib file:  
    build/lib.$os-$arch-cpython-$version/boring....  
  
  ### Windows:  
    build/lib.win-$arch-cpython-$version/boringssl.pyd  
  
  ### Mac:
    build/lib.macosx-10.9-x86_64-cpython-$version/boringssl.abi3.so
  
  ### Android:
    build/lib.linux-aarch64-cpython-$version/boringssl.abi3.so
  
  ### Linux:
    build/lib.linux-x86_64-$version/boringssl.abi3.so
  