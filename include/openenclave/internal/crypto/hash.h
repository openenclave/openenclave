// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HASH_H
#define _OE_HASH_H

#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

/* Message digest types supported by RSA and EC digital signing */
typedef enum _oe_hash_type
{
    OE_HASH_TYPE_SHA256,
    OE_HASH_TYPE_SHA512,
    __OE_HASH_TYPE_MAX = OE_ENUM_MAX,
} oe_hash_type_t;

OE_STATIC_ASSERT(sizeof(oe_hash_type_t) == sizeof(unsigned int));

OE_EXTERNC_END

#endif /* _OE_HASH_H */
