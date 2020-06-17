// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/**
 * @file asn1.h
 *
 * This file defines a minimal set of primitives for parsing ASN.1. These
 * primitives are implemented by an underlying crypto library (such as
 * mbed TLS or OpenSSL). A typical parser has the following skeleton.
 *
 *     ```
 *     oe_result_t parse(oe_asn1_t* asn1)
 *     {
 *         oe_result_t result;
 *
 *         while (oe_asn1_more(asn1))
 *         {
 *             oe_asn1_tag_t tag;
 *
 *             result = oe_asn1_peek_tag(asn1, &tag);
 *
 *             if (result != OE_OK)
 *                 goto done;
 *
 *             switch (tag)
 *             {
 *                 case OE_ASN1_TAG_SEQUENCE:
 *                 {
 *                     oe_asn1_t sequence;
 *
 *                     result = oe_asn1_get_sequence(asn1, &sequence);
 *
 *                     if (result != OE_OK)
 *                         goto done;
 *
 *                     result = _parse(&sequence);
 *
 *                     break;
 *                 }
 *                 case OE_ASN1_TAG_INTEGER:
 *                 {
 *                     int value;
 *
 *                     result = oe_asn1_get_integer(asn1, &value);
 *
 *                     if (result != OE_OK)
 *                         goto done;
 *
 *                     break;
 *                 }
 *                 case OE_ASN1_TAG_OID:
 *                 {
 *                     oe_oid_string_t oid;
 *
 *                     result = oe_asn1_get_oid(asn1, &oid);
 *
 *                     if (result != OE_OK)
 *                         goto done;
 *
 *                     break;
 *                 }
 *                 case OE_ASN1_TAG_OCTET_STRING:
 *                 {
 *                     const uint8_t* data;
 *                     size_t length;
 *
 *                     result = oe_asn1_get_octet_string(asn1, &data, &length);
 *
 *                     if (result != OE_OK)
 *                         goto done;
 *
 *                     break;
 *                 }
 *                 default:
 *                 {
 *                     oe_asn1_tag_t tag;
 *                     size_t length;
 *                     const uint8_t* data;
 *
 *                     result = oe_asn1_get_raw(asn1, &tag, &data, &length);
 *
 *                     if (result != OE_OK)
 *                         goto done;
 *
 *                     break;
 *                 }
 *             }
 *         }
 *
 *         result = OE_OK;
 *
 *     done:
 *         return result;
 *     }
 *     ```
 *
 * The functions below support:
 *
 *     - Initializing an ASN.1 input stream.
 *     - Getting ASN.1 sequence elements from the stream.
 *
 * The following snippet initializes an ASN.1 input context.
 *
 *     ```
 *     oe_asn1_t asn1;
 *     oe_asn1_init(&asn1, data, length);
 *     ```
 */

#ifndef _OE_ASN1_H
#define _OE_ASN1_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include "oid.h"

OE_EXTERNC_BEGIN

/* Standard ASN.1 tag numbers */
#define OE_ASN1_TAG_EOC 0x00
#define OE_ASN1_TAG_BOOLEAN 0x01
#define OE_ASN1_TAG_INTEGER 0x02
#define OE_ASN1_TAG_BIT_STRING 0x03
#define OE_ASN1_TAG_OCTET_STRING 0x04
#define OE_ASN1_TAG_NULL 0x05
#define OE_ASN1_TAG_OID 0x06
#define OE_ASN1_TAG_OBJECT_DESCRIPTOR 0x07
#define OE_ASN1_TAG_EXTERNAL 0x08
#define OE_ASN1_TAG_REAL 0x09
#define OE_ASN1_TAG_ENUMERATED 0x0a
#define OE_ASN1_TAG_EMBEDDED_PDV 0x0b
#define OE_ASN1_TAG_UTF8_STRING 0x0c
#define OE_ASN1_TAG_RELATIVE_OID 0x0d
#define OE_ASN1_TAG_SEQUENCE 0x10
#define OE_ASN1_TAG_SET 0x11
#define OE_ASN1_TAG_NUMERIC_STRING 0x12
#define OE_ASN1_TAG_PRINTABLE_STRING 0x13
#define OE_ASN1_TAG_T61_STRING 0x14
#define OE_ASN1_TAG_VIDEOTEX_STRING 0x15
#define OE_ASN1_TAG_IA5_STRING 0x16
#define OE_ASN1_TAG_UTC_TIME 0x17
#define OE_ASN1_TAG_GENERALIZED_TIME 0x18
#define OE_ASN1_TAG_GRAPHIC_STRING 0x19
#define OE_ASN1_TAG_VISIBLE_STRING 0x1a
#define OE_ASN1_TAG_GENERAL_STRINTG 0x1b
#define OE_ASN1_TAG_UNIVERSAL_STRING 0x1c
#define OE_ASN1_TAG_CHARACTER_STRING 0x1d
#define OE_ASN1_TAG_BMP_STRING 0x1e

/* Standard ASN.1 value encodings */
#define OE_ASN1_TAG_PRIMITIVE 0x00
#define OE_ASN1_TAG_CONSTRUCTED 0x20

/* Input stream for ASN.1 functions below */
typedef struct _oe_asn1_t
{
    const uint8_t* data;
    size_t length;
    const uint8_t* ptr;
} oe_asn1_t;

typedef int oe_asn1_tag_t;

/**
 * Initializes an ASN.1 input stream.
 *
 * An ASN.1 input stream consists of three fields.
 *     - **data** - a pointer to the ASN.1 data.
 *     - **length** - the length of the ASN.1 data.
 *     - **ptr** - a pointer to the current byte in the stream.
 *
 * The parsing functions below advance the **ptr** field until all data is
 * exhausted (when **ptr** == **data** + **length**).
 *
 * @param asn1 the ASN.1 input stream.
 * @param data pointer to the start of the ASN.1 data.
 * @param length the length of the ASN.1 data.
 */
OE_INLINE void oe_asn1_init(oe_asn1_t* asn1, const uint8_t* data, size_t length)
{
    asn1->data = data;
    asn1->length = length;
    asn1->ptr = asn1->data;
}

/**
 * Returns true if there is more data in the ASN.1 input stream.
 *
 * @param asn1 the ASN.1 input stream.
 *
 * @return true if there is more data in the ASN.1 input stream.
 */
OE_INLINE bool oe_asn1_more(const oe_asn1_t* asn1)
{
    return asn1->ptr < asn1->data + asn1->length;
}

/**
 * Gets a sequence element from the ASN.1 input stream.
 *
 * This function gets a sequence element from the ASN.1 input stream and
 * advances the current position just beyond that element.
 *
 * @param asn1[in,out] the ASN.1 input stream.
 * @param sequence[out] a newly initialized ASN.1 input stream containing the
 *        sequence.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1, oe_asn1_t* sequence);

OE_EXTERNC_END

#endif /* _OE_ASN1_H */
