#ifndef _OE_LIBC_DEPRECATIONS_H
#define _OE_LIBC_DEPRECATIONS_H

#define __NEED_size_t
#include <bits/alltypes.h>

#if defined(OE_LIBC_SUPPRESS_DEPRECATIONS)
# define OE_LIBC_DEPRECATED(MSG)
#else
# define OE_LIBC_DEPRECATED(MSG) __attribute__((deprecated(MSG)))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

OE_LIBC_DEPRECATED("unsafe function")
char* strcpy(char* dest, const char* src);

OE_LIBC_DEPRECATED("unsafe function")
char* strcat(char* dest, const char* src);

OE_LIBC_DEPRECATED("unsafe function")
size_t strlen(const char* s);

#if defined(__cplusplus)
}
#endif

#endif /* _OE_LIBC_DEPRECATIONS_H */
