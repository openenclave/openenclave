EnclaveLibc
===========

**EnclaveLibc** is a tiny subset of the standard C library that resides within
the **oeenclave** library. It defines functions with standard C signatures but 
whose names are prefixed with **"oe"**. For example, **strlen** is defined as 
follows.

```
size_t oe_strlen(const char* s);
```

**EnclaveLibc** is used within the **oeenclave** library itself but is also
used as a vehicle for porting third-party libraries such as **"mbed TLS"**. 
For an example of the latter, please see the section entitled **"Porting mbed 
TLS"**.

enclavelibc.h
-------------

The **enclavelibc.h** header file declares all **EnclaveLibc** functions and
is located here in the source tree.

```
./include/openenclave/internal/enclavelibc.h
```

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

Sources containing the corresponding function definitions are located in the 
following directory.

```
./enclave/enclavelibc
```

Porting mbed TLS
----------------

This section describes the general approach used to port **mbed TLS**.

### The standard C headers

**EnclaveLibc** provides a sparse subset of standard C headers located under
the following directory in the source tree.

```
../include/openenclave/internal/enclavelibc
```

This directory contains the following standard C headers.

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

Each header defines a sparse subset of the standard C functions.

