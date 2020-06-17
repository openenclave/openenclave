// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>

#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#if defined(OE_INLINE)
#undef OE_INLINE
#define OE_INLINE
#endif
#include <openenclave/corelibc/bits/atexit.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

extern int oe_cxa_atexit(void (*func)(void*), void* arg, void* dso_handle);

int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle)
{
    return oe_cxa_atexit(func, arg, dso_handle);
}
