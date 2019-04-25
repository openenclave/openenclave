// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_BITS_DEFS_H
#define _OE_CORELIBC_BITS_DEFS_H

#include <openenclave/bits/defs.h>

#ifdef __GNUC__
#define OE_NO_RETURN __attribute__((__noreturn__))
#else
#define OE_NO_RETURN
#endif

#endif /* _OE_CORELIBC_BITS_DEFS_H */
