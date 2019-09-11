// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CXA_ATEXIT_H
#define _OE_CXA_ATEXIT_H

int oe_cxa_atexit(void (*func)(void*), void* arg, void* dso_handle);

#endif /* _OE_CXA_ATEXIT_H */
