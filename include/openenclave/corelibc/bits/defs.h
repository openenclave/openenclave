// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_BITS_DEFS_H
#define _OE_CORELIBC_BITS_DEFS_H

#include <openenclave/bits/defs.h>

#if __STDC_VERSION__ >= 199901L
#define OE_RESTRICT restrict
#elif !defined(__GNUC__) || defined(__cplusplus)
#define OE_RESTRICT
#endif

#endif /* _OE_CORELIBC_BITS_DEFS_H */
