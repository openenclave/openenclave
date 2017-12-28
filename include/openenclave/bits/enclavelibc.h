#ifndef _OE_ENCLAVE_LIBC_H
#define _OE_ENCLAVE_LIBC_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

/**
 * Enclave implementation of the standard strlen() function.
 *
 * Refer to documentation for strlen() function.
 */
size_t OE_Strlen(const char* s);

/**
 * Enclave implementation of the standard strcmp() function.
 *
 * Refer to documentation for strcmp() function.
 */
int OE_Strcmp(const char* s1, const char* s2);

/**
 * Enclave implementation of the standard strlcpy() function.
 *
 * Refer to documentation for strlcpy() function.
 */
size_t OE_Strlcpy(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of the standard strlcat() function.
 *
 * Refer to documentation for strlcat() function.
 */
size_t OE_Strlcat(char* dest, const char* src, size_t size);

/**
 * Enclave implementation of the standard memcpy() function.
 *
 * Refer to documentation for memcpy() function.
 */
void *OE_Memcpy(void *dest, const void *src, size_t n);

/**
 * Enclave implementation of the standard memset() function.
 *
 * Refer to documentation for memset() function.
 */
void *OE_Memset(void *s, int c, size_t n);

/**
 * Enclave implementation of the standard memcmp() function.
 *
 * Refer to documentation for memcmp() function.
 */
int OE_Memcmp(const void *s1, const void *s2, size_t n);

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
int OE_Vsnprintf(char* str, size_t size, const char* fmt, OE_va_list ap);

/**
 * Produce output according to a given format string.
 *
 * This function is similar to snprintf() but has limited support for format
 * types. See OE_Vsnprintf() for details on these limits.
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
int OE_Snprintf(char* str, size_t size, const char* fmt, ...);

OE_EXTERNC_END

#endif /* _OE_ENCLAVE_H */