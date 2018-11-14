// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_UNISTD_H
#define _ELIBC_UNISTD_H

#include "bits/common.h"

ELIBC_EXTERNC_BEGIN

#define ELIBC_STDIN_FILENO 0
#define ELIBC_STDOUT_FILENO 1
#define ELIBC_STDERR_FILENO 2

void* elibc_sbrk(intptr_t increment);

#if defined(ELIBC_NEED_STDC_NAMES)

#define STDIN_FILENO ELIBC_STDIN_FILENO
#define STDOUT_FILENO ELIBC_STDOUT_FILENO
#define STDERR_FILENO ELIBC_STDERR_FILENO

ELIBC_INLINE
void* sbrk(intptr_t increment)
{
    return elibc_sbrk(increment);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_UNISTD_H */
