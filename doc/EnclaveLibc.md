EnclaveLibc
===========

__EnclaveLibc__ is a tiny subset of the standard C library. It resides within 
the __oeenclave__ library. All functions in the library bear the __'_oe'__ 
prefix followed by the standard C name. For example, __'strlen'__ 

*xxx*
**xxx**
#xxx#

It provides a subset of the standard C header files,
located here in the source tree.

```
${OE_SOURCE_DIRECTORY}/include/openenclave/internal/enclavelibc
```

The implementation sources are located here.

```
${OE_SOURCE_DIRECTORY}/enclave/enclavelibc
```


