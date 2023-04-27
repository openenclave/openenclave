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
$ clang-11 ${cflags} -o enc enc.c ${libs}
```

To build an enclave application with the Clang C++ compiler, use these commands.

```
cxxflags=`pkg-config oeenclave-clang++ --cflags`
libs=`pkg-config oeenclave-clang++ --libs`
$ clang++-11 ${cxxflags} -o enc enc.cpp ${libs}
```

To build an enclave application with a specific crypto library, additional commands are needed to incorporate additional source files and headers. In this example, `OE_CRYPTO_LIB` is set to `openssl`. The values that `OE_CRYPTO_LIB` supports are:
- `mbedtls`
- `openssl`
- `openssl_symcrypt_fips`
- `openssl_3`

```
OE_CRYPTO_LIB=openssl
cxxflags=`pkg-config oeenclave-clang++ --cflags`
libs=`pkg-config oeenclave-clang++ --libs`
cryptolibs=`pkg-config oeenclave-clang++ --variable=${OE_CRYPTO_LIB}libs`
$ clang++-11 ${cxxflags} -o enc enc.cpp ${libs} ${cryptolibs}
```

OpenSSL 3.0 needs a different set of flags from cflags, because it uses additional include directories. So when building with `OE_CRYPTO_LIB` as `openssl_3`, variable `openssl_3flags` should be used in place of `cflags`.

```
cxxflags=`pkg-config oeenclave-clang++ --variable=openssl_3flags`
libs=`pkg-config oeenclave-clang++ --libs`
cryptolibs=`pkg-config oeenclave-clang++ --variable=openssl_3libs`
$ clang++-11 ${cxxflags} -o enc enc.cpp ${libs} ${cryptolibs}
```

Building host applications:
---------------------------

To build a host application with the Clang C compiler, use the following
commands.

```
cflags=`pkg-config oehost-clang --cflags`
libs=`pkg-config oehost-clang --libs`
$ clang-11 ${cflags} -o host host.c ${libs}
```

To build a host application with the Clang C++ compiler, use these commands.

```
cflags=`pkg-config oehost-clang++ --cflags`
libs=`pkg-config oehost-clang++ --libs`
$ clang++-11 ${cflags} -o host host.c ${libs}
```
