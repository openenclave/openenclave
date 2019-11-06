// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ATEXIT_H
#define _OE_ATEXIT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

int oe_atexit(void (*function)(void));

void oe_call_atexit_functions(void);

int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle);

OE_EXTERNC_END

#endif /* _OE_ATEXIT_H */
