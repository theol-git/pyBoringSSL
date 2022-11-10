import os
import sys
import shutil

from distutils.sysconfig import get_python_lib
import distutils.command.build as _build
from distutils import spawn
from setuptools import setup


def extend_build(package_name):
    class build(_build.build):

        def rename_libs(self, _build_dir):
            if sys.platform == "win32":
                shutil.copy(os.path.join(_build_dir, "boringssl", "ssl", "Release", "ssl.lib"),
                          os.path.join(_build_dir, "boringssl", "ssl", "bssl.lib"))
                shutil.copy(os.path.join(_build_dir, "boringssl", "crypto", "Release", "crypto.lib"),
                          os.path.join(_build_dir, "boringssl", "crypto", "bcrypto.lib"))
                shutil.copy(os.path.join(_build_dir, "boringssl", "decrepit", "Release", "decrepit.lib"),
                          os.path.join(_build_dir, "boringssl", "decrepit", "decrepit.lib"))

                for fn in ["brotlicommon-static.lib", "brotlidec-static.lib"]:
                    shutil.copy(os.path.join(_build_dir, "brotli", "Release", fn),
                                os.path.join(_build_dir, "brotli", fn))

                for module in ["cert_decompress", "getpeercert"]:
                    shutil.copy(os.path.join(_build_dir, module, "Release", module + ".lib"),
                                os.path.join(_build_dir, module, module + ".lib"))
            else:
                os.rename(os.path.join(_build_dir, "boringssl", "ssl", "libssl.a"),
                          os.path.join(_build_dir, "boringssl", "ssl", "libbssl.a"))
                os.rename(os.path.join(_build_dir, "boringssl", "crypto", "libcrypto.a"),
                          os.path.join(_build_dir, "boringssl", "crypto", "libbcrypto.a"))


        def run(self):
            cwd = os.getcwd()
            if spawn.find_executable('cmake') is None:
                sys.stderr.write("CMake is required to build this package.\n")
                sys.exit(-1)

            _source_dir = os.path.split(__file__)[0]
            _build_dir = os.path.join(_source_dir, 'build')
            _prefix = os.path.join(get_python_lib(), package_name)
            try:
                spawn.spawn(['cmake',
                             '-H{0}'.format(_source_dir),
                             '-B{0}'.format(_build_dir),
                             # '-DCMAKE_INSTALL_PREFIX={0}'.format(_prefix),
                             ])
                spawn.spawn(['cmake',
                             '--build', _build_dir, "-j8", "--config", "Release",
                             # '--target', 'install'
                             ])

                self.rename_libs(_build_dir)

                os.chdir(cwd)
            except spawn.DistutilsExecError:
                sys.stderr.write("Error while building with CMake\n")
                sys.exit(-1)

            _build.build.run(self)
    return build


setup(
    name='pyBoringSSL',
    version='1.0',
    author='XX-Net-Dev',
    description='A python bundle for boringSSL',
    long_description='A python bundle for boringSSL',
    url='https://github.com/XX-Net/pyBoringSSL',
    keywords='development, setup, setuptools',
    python_requires='>=3.7, <4',
    packages=[
        "boringssl"
    ],
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=['build_pyBoringSSL.py:ffibuilder'],
    install_requires=["cffi>=1.0.0"],
    cmdclass={'build': extend_build('boringSSL')},
)