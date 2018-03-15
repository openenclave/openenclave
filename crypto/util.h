// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CRYPTO_HOST_H
#define _OE_CRYPTO_HOST_H

#include <openenclave/result.h>
#include <openenclave/types.h>

OE_Result OE_CheckForNullTerminator(const void* pemData, size_t pemSize);

#endif /* _OE_CRYPTO_HOST_H */
