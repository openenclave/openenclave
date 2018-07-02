// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_UNISTD_H
#define _OE_ENCLAVELIBC_UNISTD_H

#include "bits/common.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

#define OE_STDIN_FILENO 0
#define OE_STDOUT_FILENO 1
#define OE_STDERR_FILENO 2

void* oe_sbrk(intptr_t increment);

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

#define STDIN_FILENO OE_STDIN_FILENO
#define STDOUT_FILENO OE_STDOUT_FILENO
#define STDERR_FILENO OE_STDERR_FILENO

OE_ENCLAVELIBC_INLINE
void* sbrk(intptr_t increment)
{
    return oe_sbrk(increment);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_UNISTD_H */
