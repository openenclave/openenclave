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

These files are installed into the following directory.

```
$ /usr/local/share/pkgconfig
```

Once installed, **pkg-config** may be used to obtain compiler and linker flags 
sufficient for building enclave applications with the GCC or Clang compiler.

Setting **PKG_CONFIG_PATH**
---------------------------

If **Open Enclave** is not installed with the default prefix (**/usr/local**),
the **PKG_CONFIG_PATH** variable must be set relative to that custom prefix.

Building enclave applications:
------------------------------

To build an enclave application with the Clang C compiler, use the following 
commands.

```
cflags=`pkg-config oeenclave-clang --cflags`
libs=`pkg-config oeenclave-clang --libs`
$ clang-8 ${cflags} -o enc enc.c ${libs}
```

To build an enclave application with the Clang C++ compiler, use these commands.

```
cxxflags=`pkg-config oeenclave-clang++ --cflags`
libs=`pkg-config oeenclave-clang++ --libs`
$ clang++-8 ${cxxflags} -o enc enc.cpp ${libs}
```

Building host applications:
---------------------------

To build a host application with the Clang C compiler, use the following 
commands.

```
cflags=`pkg-config oehost-clang --cflags`
libs=`pkg-config oehost-clang --libs`
$ clang-8 ${cflags} -o host host.c ${libs}
```

To build a host application with the Clang C++ compiler, use these commands.

```
cflags=`pkg-config oehost-clang++ --cflags`
libs=`pkg-config oehost-clang++ --libs`
$ clang++-8 ${cflags} -o host host.c ${libs}
```
