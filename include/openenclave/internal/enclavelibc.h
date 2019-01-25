// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_H
#define _OE_ENCLAVELIBC_H

#include <openenclave/internal/defs.h>
#include <openenclave/internal/types.h>

#if __STDC_VERSION__ >= 199901L
#define OE_RESTRICT restrict
#elif !defined(__GNUC__) || defined (__cplusplus)
#define OE_RESTRICT
#endif

OE_EXTERNC_BEGIN

/* Enclave implementations from MUSL compiled directly into oecore */
int memcmp(const void *vl, const void *vr, size_t n);
void *memcpy(void *OE_RESTRICT dest, const void *OE_RESTRICT src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memset(void *dest, int c, size_t n);

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
 * Produce output according to a given format string.
 *
 * This function is similar to vsnprintf() but has limited support for format
 * types. It only supports the following without width specifiers.
 *     - "%s"
 *     - "%u"
 *     - "%d"
 *     - "%x"
 *     - "%lu"
 *     - "%ld"
 *     - "%lx"
 *     - "%zu"
 *     - "%zd"
 *     - "%p"
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
 * Allocates space on the stack frame of the caller.
 *
 * This function allocates **SIZE** bytes of space on the stack frame of the
 * caller. The allocated space is automatically freed when the calling
 * function returns. If the stack overflows, the behavior is undefined.
 *
 * @param SIZE The number of bytes to allocate.
 *
 * @returns Returns the address of the allocated space.
 *
 */
// __builtin_alloca is appropriate for both gcc and clang.
// For MSVC, we will probably want _malloca from <malloc.h>.
#define oe_stack_alloc(SIZE) __builtin_alloca(SIZE)

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

OE_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_H */
