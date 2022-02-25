// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_LIBC_INIT_H
#define _OE_INTERNAL_LIBC_INIT_H

#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

/* Callback for initializing libc */
void oe_libc_initialize(void);

/* Test utility to check whether libc has been initialized */
bool oe_test_libc_is_initialized(void);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_LIBC_INIT_H */
