// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

#ifndef _OE_CORELIBC_BITS_DEFS_H
#define _OE_CORELIBC_BITS_DEFS_H

#include <openenclave/bits/defs.h>

/* MSVC 19.27.29111 reports a clash between the prototypes for memcpy (no
 * 'restrict' in its libc).*/
#if __STDC_VERSION__ >= 199901L && !defined(_MSC_VER)
#define OE_RESTRICT restrict
#elif !defined(__GNUC__) || defined(__cplusplus)
#define OE_RESTRICT
#endif

#endif /* _OE_CORELIBC_BITS_DEFS_H */
