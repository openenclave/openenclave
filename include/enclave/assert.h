#ifndef __ELIBC_ASSERT_H
#define __ELIBC_ASSERT_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

#define assert(COND) \
    do \
    { \
        if (!(COND)) \
        { \
            __assert_fail(#COND, __FILE__, __LINE__, __FUNCTION__); \
        } \
    } \
    while (0)

__NORETURN extern void __assert_fail(
    const char *__expr, 
    const char *__file,
    unsigned int __line, 
    const char *__function);

__ELIBC_END

#endif /* __ELIBC_ASSERT_H */
