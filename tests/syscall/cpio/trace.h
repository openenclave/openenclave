// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _CPIO_TRACE_H
#define _CPIO_TRACE_H

#include <stdio.h>

// clang-format off
#if defined(TRACE)
# define GOTO(LABEL) \
    do \
    { \
        printf("GOTO=%s(%u): %s()\n", __FILE__, __LINE__, __FUNCTION__); \
        goto LABEL; \
    } \
    while (0)
#else
# define GOTO(LABEL) goto LABEL
#endif
// clang-format on

#endif /* _CPIO_TRACE_H */
