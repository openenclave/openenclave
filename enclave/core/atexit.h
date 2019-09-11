// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ATEXIT_H
#define _OE_ATEXIT_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

int oe_atexit(void (*function)(void));

void oe_call_atexit_functions(void);

OE_EXTERNC_END

#endif /* _OE_ATEXIT_H */
