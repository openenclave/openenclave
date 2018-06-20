EnclaveLibc
===========

**EnclaveLibc** is a tiny subset of the standard C library that resides within
the **oeenclave** library. It defines functions with standard C signatures but 
whose names are prefixed with **"oe\_"**. For example, **strlen** is defined as 
follows.

```
size_t oe_strlen(const char* s);
```

**EnclaveLibc** is used within the **oeenclave** library itself but is also
used as a vehicle for porting **mbed TLS** (see **"Porting mbed TLS"** for 
details).

The <enclavelibc.h> header
--------------------------

The **<enclavelibc.h>** header file declares all **EnclaveLibc** functions and
is located here in the source tree.

[```include/openenclave/internal/enclavelibc.h```](../include/openenclave/internal/enclavelibc.h)

This header declares the following functions.

```
size_t oe_strlen(const char* s);

size_t oe_strnlen(const char* s, size_t n);

int oe_strcmp(const char* s1, const char* s2);

int oe_strncmp(const char* s1, const char* s2, size_t n);

char* oe_strncpy(char* dest, const char* src, size_t n);

char* oe_strstr(const char* haystack, const char* needle);

size_t oe_strlcpy(char* dest, const char* src, size_t size);

size_t oe_strlcat(char* dest, const char* src, size_t size);

void* oe_memcpy(void* dest, const void* src, size_t n);

void* oe_memset(void* s, int c, size_t n);

int oe_memcmp(const void* s1, const void* s2, size_t n);

void* oe_memmove(void* dest, const void* src, size_t n);

int oe_vsnprintf(char* str, size_t size, const char* format, oe_va_list ap);

int oe_vprintf(const char* format, oe_va_list ap);

oe_time_t oe_time(oe_time_t* tloc);

struct oe_tm* oe_gmtime(const oe_time_t* timep);

struct oe_tm* oe_gmtime_r(const oe_time_t* timep, struct oe_tm* result);

int oe_rand(void);

void* oe_malloc(size_t size);

void oe_free(void* ptr);

void* oe_calloc(size_t nmemb, size_t size);

void* oe_realloc(void* ptr, size_t size);

void* oe_memalign(size_t alignment, size_t size);

int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

unsigned long int oe_strtoul(const char* nptr, char** endptr, int base);
```

These functions are defined by sources in the following directory.

```
./enclave/enclavelibc
```

The standard C headers
----------------------

**EnclaveLibc** provides a sparse subset of standard C headers. These headers
are intended to ease porting of **mbed TLS** (and possibly other third-party
libraries in the future). These headers are located under the following 
directory in the source tree.

```
include/openenclave/internal/enclavelibc
```

This directory contains the following headers.

```
stdlib.h
limits.h
stdarg.h
stddef.h
stdio.h
sched.h
stdint.h
time.h
string.h
bits/common.h
sys/time.h
```

Each header defines various standard C functions. Each function is an 
inline wrapper around the corresponding oe-prefixed function defined in 
**<enclavelibc.h>**. For example, consider the definition of **memcpy** from
the **<string.h>** header.

```
OE_INLINE
void* memcpy(void* dest, const void* src, size_t n)
{
    return oe_memcpy(dest, src, n);
}

```

The caller of **memcpy** is redirected to **oe\_memcpy** so that the caller's
object file contains a reference to **oe\_memcpy** rather than **memcpy**.

Porting mbed TLS
----------------

This section describes the general procedure for porting **mbed TLS** to use
**EnclaveLibc**.

### Including the EnclaveLibc standard C headers

The **mbed TLS** sources must be recompiled against the **EnclaveLibc** 
standard C headers. Assuming that **${OE\_SOURCE\_DIR}** refers to the source 
of the Open Enclave source tree, use the following compiler options.

```
-nostdc -I${OE_SOURCE_DIR}/include/openenclave/internal/enclavelibc
```

These options force the compiler to use the standard C headers provided by
**EnclaveLibc** rather than the system.

Building **mbed TLS** produces the following libraries.

```
libmbedtls.a
libmbedx509.a
libmbedcrypto.a
```

These three libraries are merged into a single library.

```
liboembedtls.a
```

### Linking **oeenclave** with the **oembedtls** library

The correct linking order places **oeenclave** before **oembedtls**. Use the 
following linker options on Linux systems.

```
-loeenclave -loembedtls
```

The reader might wonder how this can work since **oembedtls** depends on the 
standard C functions defined in **oeenclave**.

The GCC linker is a single-pass linker. It builds a working set of symbols as 
it passes through the library list. If a symbol defined in an earlier library
is referenced by that earlier library (so that it is placed in the working set)
then a later library may reference that same symbol without failure (finding 
it in the working set). Therefore **oeenclave** intentionally references all 
symbols in **EnclaveLibc** so that they will be in the working set before 
**oembedtls** is processed.  To enforce this behavior, the **oeenclave** 
library provides the following function.

```
oe_link_enclavelibc();
```

This function is called indirectly from the **oeenclave** library's entry
point (**oe\_main**). It simply returns a vector of pointers to all functions 
in **EnclaveLibc**, ensuring they are statically referenced.

