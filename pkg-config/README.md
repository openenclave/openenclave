Open Enclave pkg-config files:
==============================

This directory contains a **pkg-config** file that is installed in the 
following directory.

```
$ /usr/local/share/pkgconfig/openenclave.pc
```

Once installed, **pkg-config** may be used to obtain compiler and linker flags 
sufficient for building enclave applications.

Building an enclave application:
--------------------------------

To build an enclave application, use the following commands.

```
cflags=`pkg-config openenclave --cflags`
libs=`pkg-config openenclave --libs`
$ gcc ${cflags} -o enc enc.c ${libs}
```
