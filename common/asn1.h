// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMON_ASN1_H
#define _OE_COMMON_ASN1_H

#include <openenclave/internal/asn1.h>

OE_INLINE const uint8_t* oe_asn1_end(const oe_asn1_t* asn1)
{
    return asn1->data + asn1->length;
}

/* Cast away constness for MBEDTLS ASN.1 functions */
OE_INLINE uint8_t** oe_asn1_pptr(const oe_asn1_t* asn1)
{
    return (uint8_t**)&asn1->ptr;
}

OE_INLINE bool oe_asn1_is_valid(const oe_asn1_t* asn1)
{
    if (!asn1 || !asn1->data || !asn1->length || !asn1->ptr)
        return false;

    if (!(asn1->ptr >= asn1->data && asn1->ptr <= oe_asn1_end(asn1)))
        return false;

    return true;
}

OE_INLINE size_t oe_asn1_remaining(const oe_asn1_t* asn1)
{
    return (size_t)(oe_asn1_end(asn1) - asn1->ptr);
}

oe_result_t oe_asn1_get_tag(
    oe_asn1_t* asn1,
    bool* constructed,
    oe_asn1_tag_t* tag);

oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1, oe_asn1_tag_t* tag);

#endif /* _OE_COMMON_ASN1_H */
