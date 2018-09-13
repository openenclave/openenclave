Open Enclave pkg-config files:
==============================

This directory defines the following **pkg-config** files.

```
oeenclave-gcc.pc
oeenclave-g++.pc
oeenclave-clang.pc
oeenclave-clang++.pc
oehost-gcc.pc
oehost-g++.pc
oehost-clang.pc
oehost-clang++.pc
```

These install in the following directory.

```
$ /usr/local/share/pkgconfig
```

Once installed, **pkg-config** may be used to obtain compiler and linker flags 
sufficient for building enclave applications with the GCC or Clang compiler.

Building an enclave applications:
---------------------------------

To build a gcc enclave application, use the following commands.

```
cflags=`pkg-config oeenclave-gcc --cflags`
libs=`pkg-config oeenclave-gcc --libs`
$ gcc ${cflags} -o enc enc.c ${libs}
```

To build a g++ enclave application, use these commands.

```
cxxflags=`pkg-config oeenclave-g++ --cflags`
libs=`pkg-config oeenclave-g++ --libs`
$ gcc ${cxxflags} -o enc enc.cpp ${libs}
```

Building host applications:
---------------------------

To build a gcc host application, use the following commands.

```
cflags=`pkg-config oehost-gcc --cflags`
libs=`pkg-config oehost-gcc --libs`
$ gcc ${cflags} -o host host.c ${libs}
```

To build a Clang C++ host application, use the following commands.

```
cflags=`pkg-config oehost-clang++ --cflags`
libs=`pkg-config oehost-clang++ --libs`
$ gcc ${cflags} -o host host.c ${libs}
```
