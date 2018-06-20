EnclaveLibc
===========

__EnclaveLibc__ is a tiny subset of the standard C library. It defines a subset
of standard C library whose function bear the **oe_** preix. Currently it 
supports the following functions.

```
size_t (*strlen)(const char* s);
size_t (*strnlen)(const char* s, size_t n);
int (*strcmp)(const char* s1, const char* s2);
int (*strncmp)(const char* s1, const char* s2, size_t n);
char* (*strncpy)(char* dest, const char* src, size_t n);
char* (*strstr)(const char* haystack, const char* needle);
size_t (*strlcpy)(char* dest, const char* src, size_t size);
size_t (*strlcat)(char* dest, const char* src, size_t size);
void* (*memcpy)(void* dest, const void* src, size_t n);
void* (*memset)(void* s, int c, size_t n);
int (*memcmp)(const void* s1, const void* s2, size_t n);
void* (*memmove)(void* dest, const void* src, size_t n);
int (*vsnprintf)(char* str, size_t size, const char* format, oe_va_list ap);
int (*vprintf)(const char* format, oe_va_list ap);
oe_time_t (*time)(oe_time_t* tloc);
struct oe_tm* (*gmtime)(const oe_time_t* timep);
struct oe_tm* (*gmtime_r)(const oe_time_t* timep, struct oe_tm* result);
int (*rand)(void);
void* (*malloc)(size_t size);
void (*free)(void* ptr);
void* (*calloc)(size_t nmemb, size_t size);
void* (*realloc)(void* ptr, size_t size);
void* (*memalign)(size_t alignment, size_t size);
int (*posix_memalign)(void** memptr, size_t alignment, size_t size);
unsigned long int (*strtoul)(const char* nptr, char** endptr, int base);
```


```
${OE_SOURCE_DIRECTORY}/include/openenclave/internal/enclavelibc
```

The implementation sources are located here.

```
${OE_SOURCE_DIRECTORY}/enclave/enclavelibc
```


