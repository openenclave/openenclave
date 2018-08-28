// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENDIAN_PATCH_H
#define _ENDIAN_PATCH_H

/* Suppress this warning in the MUSL endian.h header. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wparentheses"
#include "__endian.h"
#pragma GCC diagnostic pop

#endif /* _ENDIAN_PATCH_H */
