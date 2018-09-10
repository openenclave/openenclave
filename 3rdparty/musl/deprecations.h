#ifndef _OE_LIBC_DEPRECATIONS_H
#define _OE_LIBC_DEPRECATIONS_H

#if !defined(OE_LIBC_SUPPRESS_DEPRECATIONS) && !defined(__ASSEMBLER__)

#define __NEED_size_t
#include <bits/alltypes.h>

#if defined(__cplusplus)
#define OE_LIBC_EXTERN_C_BEGIN extern "C" {
#define OE_LIBC_EXTERN_C_END }
#else
#define OE_LIBC_EXTERN_C_BEGIN
#define OE_LIBC_EXTERN_C_END
#endif

#define OE_LIBC_DEPRECATED(MSG) __attribute__((deprecated(MSG)))

OE_LIBC_EXTERN_C_BEGIN

OE_LIBC_DEPRECATED("unsafe function")
char* strcpy(char* dest, const char* src);

OE_LIBC_DEPRECATED("unsafe function")
char* strcat(char* dest, const char* src);

OE_LIBC_DEPRECATED("unsafe function")
size_t strlen(const char* s);

OE_LIBC_EXTERN_C_END

#endif /* !defined(OE_LIBC_SUPPRESS_DEPRECATIONS) */

#endif /* _OE_LIBC_DEPRECATIONS_H */
