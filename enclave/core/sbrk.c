// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>

/*
**==============================================================================
**
** oe_sbrk()
**
**     This function is similar to sbrk(). See the sbrk() manual page for
**     details.
**
**     As a security precaution, oe_sbrk() zero-initializes newly allocated
**     memory. Recall that the enclave loader neither initializes nor measures
**     heap memory, and since the host determines the contents of the heap,
**     badly behaved programs that fail to initialize memory obtained with
**     oe_sbrk() are vulnerable to various attacks. To mitigate these attacks,
**     oe_sbrk() incrementally zero-fills newly acquired memory. Note that this
**     protects malloc() and realloc() as well since dlmalloc is based solely
**     on oe_sbrk().
**
**==============================================================================
*/

void* oe_sbrk(ptrdiff_t increment)
{
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
    static uint8_t* _base;
    static uint8_t* _end;
    static uint8_t* _max;
    static uint8_t* _break;
    uint8_t* ret = (uint8_t*)-1;

    oe_spin_lock(&_lock);

    /* Initialize on the first call. */
    if (!_base)
    {
        _base = (uint8_t*)__oe_get_heap_base();
        _end = (uint8_t*)__oe_get_heap_end();
        _max = _base;
        _break = _max;
    }

    if (increment > 0)
    {
        ptrdiff_t delta = _end - _break;

        if (increment > delta)
            goto done;

        ret = _break;
        _break += increment;

        if (_break > _max)
        {
            /* Zero-initializes newly allocated memory. */
            memset(_max, 0, (size_t)(_break - _max));
            _max = _break;
        }
    }
    else if (increment < 0)
    {
        ptrdiff_t delta = _break - _base;
        ptrdiff_t decrement = -increment;

        if (decrement > delta)
            goto done;

        ret = _break;
        _break -= decrement;
    }
    else
    {
        /* increment is zero, so return the current break value. */
        ret = _break;
    }

done:

    oe_spin_unlock(&_lock);

    return ret;
}
