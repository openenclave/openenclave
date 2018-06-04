#ifndef _OE_BITS_FORMAT_H
#define _OE_BITS_FORMAT_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

/*
**==============================================================================
**
** OE_TO_LLU()
** OE_TO_LLD()
** OE_TO_LLX()
**
** These macros work around printf-format specifier incompatibilities across
** platforms. To illustrate the problem, consider the following snippet.
**
**     uint64_t x = 0;
**     printf("%lu\n", x);
**
** GCC compiles the above without warning, whereas MSVC warns that 'x' and
** '%lu' are incompatible. Now consider the following snippet.
**
**     uint64_t x = 0;
**     printf("%llu\n", x);
**
** GCC warns that 'x' and '%llu' are incompatible, whereas MSVC compiles
** without warning. To work around this, the OE_TO_LLU() macro is applied as
** follows.
**
**     uint64_t x = 0;
**     printf("%llu\n", OE_TO_LLU(x));
**
** It is important to note that the OE_TO_LLU() macro neither casts nor promotes
** its argument, rather it converts the type of its argument from 'uint64_t'
** to 'unsigned long long', without changing the size of the integer. Note that
** the following assumption holds on all supported platforms.
**
**     sizeof(unsigned long long) == sizeof(uint64_t)
**
** Also the OE_TO_LLU() macro fails to compile when its argument is not
** 'uint64_t' For example, the following snippet results in a compiler error.
**
**     uint32_t x = 0;
**     printf("%llu\n", OE_TO_LLU(x)); // compiler error!
**
** To implement this macro, GCC requires a type conversion whereas MSVC does not
** (since the type of the argument already matches '%llu').
**
**==============================================================================
*/

#if defined(_MSC_VER)

#define OE_TO_LLU(_X_) _X_
#define OE_TO_LLD(_X_) _X_
#define OE_TO_LLX(_X_) _X_

#elif defined(__GNUC__)

OE_INLINE unsigned long long OE_ToLLU(const uint64_t* ptr)
{
    OE_STATIC_ASSERT(sizeof(unsigned long long) == sizeof(uint64_t));
    return *ptr;
}

OE_INLINE long long OE_ToLLD(const int64_t* ptr)
{
    OE_STATIC_ASSERT(sizeof(long long) == sizeof(int64_t));
    return *ptr;
}

#define OE_TO_LLU(_X_)           \
    ({                           \
        __typeof(_X_) _x_ = _X_; \
        OE_ToLLU(&_x_);          \
    })

#define OE_TO_LLD(_X_)           \
    ({                           \
        __typeof(_X_) _x_ = _X_; \
        OE_ToLLD(&_x_);          \
    })

#define OE_TO_LLX(_X_) OE_TO_LLU(_X_)

#endif /* defined(__GNUC__) */

#endif /* _OE_BITS_FORMAT_H */
