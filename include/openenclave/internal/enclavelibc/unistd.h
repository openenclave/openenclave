#ifndef _OE_ENCLAVELIBC_UNISTD_H
#define _OE_ENCLAVELIBC_UNISTD_H

#include "bits/common.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

void* oe_sbrk(intptr_t increment);

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

OE_ENCLAVELIBC_INLINE
void* sbrk(intptr_t increment)
{
    return oe_sbrk(increment);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_UNISTD_H */
