// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_MUSL_PATCHES_ENDIAN_H
#define _OE_MUSL_PATCHES_ENDIAN_H

/* Suppress this warning in the MUSL endian.h header. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wconversion"
#include "__endian.h"
#pragma GCC diagnostic pop

#endif /* _OE_MUSL_PATCHES_ENDIAN_H */
