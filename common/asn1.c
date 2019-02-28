// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "asn1.h"
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/raise.h>

oe_result_t oe_asn1_get_tag(
    oe_asn1_t* asn1,
    bool* constructed,
    oe_asn1_tag_t* tag)
{
    oe_result_t result = OE_UNEXPECTED;

    if (constructed)
        *constructed = false;

    if (tag)
        *tag = 0;

    if (!oe_asn1_is_valid(asn1) || !constructed || !tag)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        const int mask = 0x1f;
        int short_tag = *asn1->ptr & mask;
        *constructed = *asn1->ptr & OE_ASN1_TAG_CONSTRUCTED;

        if (short_tag == mask)
        {
            long long_tag = 0;

            asn1->ptr++;

            if (oe_asn1_remaining(asn1) < 1)
                OE_RAISE(OE_FAILURE);

            while (*asn1->ptr & 0x80)
            {
                long_tag <<= 7L;
                long_tag |= *asn1->ptr & 0x7f;
                asn1->ptr++;

                if (oe_asn1_remaining(asn1) < 1)
                    OE_RAISE(OE_FAILURE);

                if (long_tag > (OE_INT_MAX >> 7L))
                    OE_RAISE(OE_FAILURE);
            }

            long_tag <<= 7L;
            long_tag |= *(asn1->ptr++) & 0x7f;

            *tag = (oe_asn1_tag_t)long_tag;
        }
        else
        {
            *tag = short_tag;
            asn1->ptr++;
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1, oe_asn1_tag_t* tag)
{
    oe_result_t result = OE_UNEXPECTED;
    bool constructed;

    if (!oe_asn1_is_valid(asn1) || !tag)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Use a temporary so _get_tag() will not update the ASN.1 cursor */
    {
        oe_asn1_t tmp_asn1 = *asn1;
        OE_CHECK(oe_asn1_get_tag(&tmp_asn1, &constructed, tag));
    }

    result = OE_OK;

done:
    return result;
}
