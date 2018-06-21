// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_H
#define _OE_ENCLAVELIBC_H

#include "../bits/defs.h"
#include "../bits/types.h"

OE_EXTERNC_BEGIN

typedef long oe_time_t;

typedef struct _OE_FILE OE_FILE;

struct oe_tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

/**
 * Enclave implementation of the standard strlen() function.
 *
 * Refer to documentation for strlen() function.
 */
size_t oe_strlen(const char* s);

/**
 * Enclave implementation of the standard strnlen() function.
 *
 * Refer to documentation for strnlen() function.
 */
size_t oe_strnlen(const char* s, size_t n);

/**
 * Enclave implementation of the standard strcmp() function.
 *
 * Refer to documentation for strcmp() function.
 */
int oe_strcmp(const char* s1, const char* s2);

/**
 * Enclave implementation of the standard strncmp() function.
 *
 * Refer to documentation for strncmp() function.
 */
int oe_strncmp(const char* s1, const char* s2, size_t n);

/**
 * Enclave implementation of the standard strncpy() function.
 *
 * Refer to documentation for strncpy() function.
 */
char* oe_strncpy(char* dest, const char* src, size_t n);

/**
 * Enclave implementation of the standard strstr() function.
 *
 * Refer to documentation for strstr() function.
 */
char* oe_strstr(const char* haystack, const char* needle);

/**
 * Enclave implementation of the standard strlcpy() function.
 *
 * Refer to documentation for strlcpy() function.
 */
size_t oe_strlcpy(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of the standard strlcat() function.
 *
 * Refer to documentation for strlcat() function.
 */
size_t oe_strlcat(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of the standard strerror() function.
 *
 * Refer to documentation for strerror() function.
 */
char* oe_strerror(int errnum);

/**
 * Enclave implementation of the standard strerror_r() function.
 *
 * Refer to documentation for strerror_r() function.
 */
int oe_strerror_r(int errnum, char* buf, size_t buflen);

/**
 * Enclave implementation of the standard memcpy() function.
 *
 * Refer to documentation for memcpy() function.
 */
void* oe_memcpy(void* dest, const void* src, size_t n);

/**
 * Enclave implementation of the standard memset() function.
 *
 * Refer to documentation for memset() function.
 */
void* oe_memset(void* s, int c, size_t n);

/**
 * Enclave implementation of the standard memcmp() function.
 *
 * Refer to documentation for memcmp() function.
 */
int oe_memcmp(const void* s1, const void* s2, size_t n);

/**
 * Enclave implementation of the standard memmove() function.
 *
 * Refer to documentation for memmove() function.
 */
void* oe_memmove(void* dest, const void* src, size_t n);

/**
 * Produce output according to a given format string.
 *
 * This function is similar to vsnprintf() but has limited support for format
 * types. It does not support format specifiers for floating-point types.
 *
 * @param str Write output to this string
 * @param size The size of **str** parameter.
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that would be written excluding the
 * zero-terminator. If this value is greater or equal to **size**, then the
 * string was truncated.
 *
 */
int oe_vsnprintf(char* str, size_t size, const char* fmt, oe_va_list ap);

/**
 * Produce output according to a given format string.
 *
 * This function is similar to snprintf() but has limited support for format
 * types. See oe_vsnprintf() for details on these limits.
 *
 * @param str Write output to this string.
 * @param size The size of **str** parameter.
 * @param fmt The limited printf style format.
 *
 * @returns The number of characters that would be written excluding the
 * zero-terminator. If this value is greater or equal to **size**, then the
 * string was truncated.
 *
 */
OE_PRINTF_FORMAT(3, 4)
int oe_snprintf(char* str, size_t size, const char* fmt, ...);

/**
 * Enclave implementation of the standard vprintf() function.
 *
 * Refer to documentation for vprintf() function.
 */
int oe_vprintf(const char* fmt, oe_va_list ap);

/**
 * Allocates space on the stack frame of the caller.
 *
 * This function allocates **size** bytes of space on the stack frame of the
 * caller. The returned address will be a multiple of **alignment** (if
 * non-zero). The allocated space is automatically freed when the calling
 * function returns. If the stack overflows, the behavior is undefined.
 *
 * @param size The number of bytes to allocate.
 * @param alignment The alignment requirement (see above).
 *
 * @returns Returns the address of the allocated space.
 *
 */
OE_ALWAYS_INLINE OE_INLINE void* oe_stack_alloc(size_t size, size_t alignment)
{
    void* ptr = __builtin_alloca(size + alignment);

    if (alignment)
        ptr = (void*)(((uint64_t)ptr + alignment - 1) / alignment * alignment);

    return ptr;
}

/**
 * Enclave implementation of the standard Unix sbrk() system call.
 *
 * This function provides an enclave equivalent to the sbrk() system call.
 * It increments the current end of the heap by **increment** bytes. Calling
 * oe_sbrk() with an increment of 0, returns the current end of the heap.
 *
 * @param increment Number of bytes to increment the heap end by.
 *
 * @returns The old end of the heap (before the increment) or (void*)-1 if
 * there are less than **increment** bytes left on the heap.
 *
 */
void* oe_sbrk(ptrdiff_t increment);

/**
 * Enclave implementation of the standard strtoul() function.
 *
 * Refer to documentation for strtoul() function.
 */
unsigned long int oe_strtoul(const char* nptr, char** endptr, int base);

/**
 * Enclave implementation of the standard time() function.
 *
 * Refer to documentation for time() function.
 */
oe_time_t oe_time(oe_time_t* tloc);

/**
 * Enclave implementation of the standard gmtime_t() function.
 *
 * Refer to documentation for gmtime_t() function.
 */
struct oe_tm* oe_gmtime(const oe_time_t* timep);

/**
 * Enclave implementation of the standard gmtime_t() function.
 *
 * Refer to documentation for gmtime_t() function.
 */
struct oe_tm* oe_gmtime_r(const oe_time_t* timep, struct oe_tm* result);

/**
 * Enclave implementation of the standard rand() function.
 *
 * Refer to documentation for rand() function.
 */
int oe_rand(void);

/**
 * Enclave implementation of the standard malloc() function.
 *
 * Refer to documentation for malloc() function.
 */
void* oe_malloc(size_t size);

/**
 * Enclave implementation of the standard free() function.
 *
 * Refer to documentation for free() function.
 */
void oe_free(void* ptr);

/**
 * Enclave implementation of the standard calloc() function.
 *
 * Refer to documentation for calloc() function.
 */
void* oe_calloc(size_t nmemb, size_t size);

/**
 * Enclave implementation of the standard realloc() function.
 *
 * Refer to documentation for realloc() function.
 */
void* oe_realloc(void* ptr, size_t size);

/**
 * Enclave implementation of the standard posix_memalign() function.
 *
 * Refer to documentation for posix_memalign() function.
 */
int oe_posix_memalign(void** memptr, size_t alignment, size_t size);

/**
 * Enclave implementation of the standard memalign() function.
 *
 * Refer to documentation for memalign() function.
 */
void* oe_memalign(size_t alignment, size_t size);

/**
 * Returns the location of errno for this thread.
 */
int* __oe_errno_location(void);

OE_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_H */
