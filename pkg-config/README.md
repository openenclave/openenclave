Open Enclave pkg-config files:
==============================

This directory contains a **pkg-config** file that is installed in the 
following directory.

```
$ /usr/local/share/pkgconfig/oeenclave.pc
```

Once installed, **pkg-config** may be used to obtain compiler and linker flags 
sufficient for building enclave applications.

Building an enclave application:
--------------------------------

To build an enclave application, use the following commands.

```
cflags=`pkg-config oeenclave --cflags`
libs=`pkg-config oeenclave --libs`
$ gcc ${cflags} -o enc enc.c ${libs}
```

To build a C++ enclave application, use these commands.

```
cxxflags=`pkg-config oeenclave --cflags`
libs=`pkg-config oeenclave++ --libs`
$ gcc ${cxxflags} -o enc enc.cpp ${libs}
```

Building a host application (C or C++):
---------------------------------------

To build an host application, use the following commands.

```
cflags=`pkg-config oehost --cflags`
libs=`pkg-config oehost --libs`
$ gcc ${cflags} -o host host.c ${libs}
```
