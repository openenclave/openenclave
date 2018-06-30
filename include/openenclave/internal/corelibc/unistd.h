#ifndef _OE_CORELIBC_UNISTD_H
#define _OE_CORELIBC_UNISTD_H

#include "bits/common.h"

OE_CORELIBC_EXTERNC_BEGIN

void* oe_sbrk(intptr_t increment);

#if !defined(OE_CORELIBC_HIDE_STDC_NAMES)

OE_CORELIBC_INLINE 
void* sbrk(intptr_t increment)
{
    return oe_sbrk(increment);
}

#endif /* !defined(OE_CORELIBC_HIDE_STDC_NAMES) */

OE_CORELIBC_EXTERNC_END

#endif /* _OE_CORELIBC_UNISTD_H */
