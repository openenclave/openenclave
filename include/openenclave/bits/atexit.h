// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ATEXIT_H
#define _OE_ATEXIT_H

#include <openenclave/defs.h>

OE_EXTERNC_BEGIN

int OE_AtExit(void (*function)(void));

void OE_CallAtExitFunctions(void);

int __cxa_atexit(void (*func)(void*), void* arg, void* dso_handle);

OE_EXTERNC_END

#endif /* _OE_ATEXIT_H */
