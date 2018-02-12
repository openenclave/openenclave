tests
=====

# Overview:

This directory contains all the unit tests for OpenEnclave. Type the following 
commands to build and run the tests from the corresponding CMake output folder.

```
# make
# ctest
```

This builds and runs all the tests except for libcxx, which is very slow to
build and run.

# Testing Linux-built enclaves on Windows

Host applications can be built on Windows but enclaves cannot. So enclaves
must be built on Linux and then copied to Windows for testing. For example,
suppose ecallenc.signed.so is built on Linux using the following steps.

```
# cd /dev/openenclave
# mkdir build
# cd build
# cmake ..
# make
```

This creates the following enclave:

```
/dev/openenclave/build/tests/ecall/enc/ecallenc.signed.so
```

On Windows, build OpenEnclave as follows (for example).

```
C:\> C:\PROGRA~2\MIB055~1\2017\Enterprise\VC\Auxiliary\Build\vcvars64.bat
C:\> cd C:\dev\openenclave
C:\> mkdir build
C:\> cd build
C:\> cmake ..
C:\> nmake

This builds OpenEnclave and creates the following host application:

```
C:\dev\openenclave\build\tests\ecall\host\ecallhost.exe
```

To test the Linux-built enclave, copy the enclave to the following directory:

```
C:\> cd C:\dev\openenclave\build\tests\ecall\host
```

And then perform the following steps.

```
C:\> cd C:\dev\openenclave\build\tests\ecall\host
C:\> ecallhost ecallenc.signed.so
```

To copy enclaves from Linux, one might use the PSCP.EXE program as follows.

```
C:\> pscp root@<hostname>:/dev/openenclave/build/tests/ecall/enc/ecallenc.signed.so .
```

