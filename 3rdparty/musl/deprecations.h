// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LIBC_DEPRECATIONS_H
#define _OE_LIBC_DEPRECATIONS_H

#if !defined(OE_LIBC_SUPPRESS_DEPRECATIONS) && !defined(__ASSEMBLER__)

#define __NEED_size_t
#define __NEED_pthread_t
#define __NEED_pthread_attr_t
#define __NEED_locale_t
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

/*
**==============================================================================
**
** <pthread.h>
**
**==============================================================================
*/

OE_LIBC_DEPRECATED("unsupported function")
int pthread_create(
    pthread_t *thread, 
    const pthread_attr_t *attr,
    void *(*start_routine) (void *), 
    void *arg);

OE_LIBC_DEPRECATED("unsupported function")
int pthread_join(pthread_t thread, void** retval);

OE_LIBC_DEPRECATED("unsupported function")
int pthread_detach(pthread_t thread);

/*
**==============================================================================
**
** <time.h>
**
**==============================================================================
*/

// Need this since including <time.h> will create a circular dependency.
struct tm;

OE_LIBC_DEPRECATED("unsupported function")
size_t strftime(
    char* s, 
    size_t max, 
    const char* format, 
    const struct tm* tm);

OE_LIBC_DEPRECATED("unsupported function")
size_t strftime_l(
    char* s,
    size_t max,
    const char* format,
    const struct tm* tm,
    locale_t loc);

OE_LIBC_EXTERN_C_END

#endif /* !defined(OE_LIBC_SUPPRESS_DEPRECATIONS) && !defined(__ASSEMBLER__) */

#endif /* _OE_LIBC_DEPRECATIONS_H */
