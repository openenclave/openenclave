// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASN1_H
#define _OE_ASN1_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include "cert.h"

OE_EXTERNC_BEGIN

/* ASN.1 tag numbers */
#define OE_ASN1_TAG_EOC                 0x00
#define OE_ASN1_TAG_BOOLEAN             0x01
#define OE_ASN1_TAG_INTEGER             0x02
#define OE_ASN1_TAG_BIT_STRING          0x03
#define OE_ASN1_TAG_OCTET_STRING        0x04
#define OE_ASN1_TAG_NULL                0x05
#define OE_ASN1_TAG_OID                 0x06
#define OE_ASN1_TAG_OBJECT_DESCRIPTOR   0x07
#define OE_ASN1_TAG_EXTERNAL            0x08
#define OE_ASN1_TAG_REAL                0x09
#define OE_ASN1_TAG_ENUMERATED          0x0a
#define OE_ASN1_TAG_EMBEDDED_PDV        0x0b
#define OE_ASN1_TAG_UTF8_STRING         0x0c
#define OE_ASN1_TAG_RELATIVE_OID        0x0d
#define OE_ASN1_TAG_SEQUENCE            0x10
#define OE_ASN1_TAG_SET                 0x11
#define OE_ASN1_TAG_NUMERIC_STRING      0x12
#define OE_ASN1_TAG_PRINTABLE_STRING    0x13
#define OE_ASN1_TAG_T61_STRING          0x14
#define OE_ASN1_TAG_VIDEOTEX_STRING     0x15
#define OE_ASN1_TAG_IA5_STRING          0x16
#define OE_ASN1_TAG_UTC_TIME            0x17
#define OE_ASN1_TAG_GENERALIZED_TIME    0x18
#define OE_ASN1_TAG_GRAPHIC_STRING      0x19
#define OE_ASN1_TAG_VISIBLE_STRING      0x1a
#define OE_ASN1_TAG_GENERAL_STRINTG     0x1b
#define OE_ASN1_TAG_UNIVERSAL_STRING    0x1c
#define OE_ASN1_TAG_CHARACTER_STRING    0x1d
#define OE_ASN1_TAG_BMP_STRING          0x1e

/* Value encodings */
#define OE_ASN1_TAG_PRIMITIVE           0x00
#define OE_ASN1_TAG_CONSTRUCTED         0x20

/* Opaque input stream for ASN.1 functions below */
typedef struct _oe_asn1_t
{
    const uint64_t __private[3];
}
oe_asn1_t;

oe_result_t oe_asn1_init(oe_asn1_t* asn1, const uint8_t* data, size_t length);

const uint8_t* oe_asn1_data(const oe_asn1_t* asn1);

size_t oe_asn1_length(const oe_asn1_t* asn1);

size_t oe_asn1_offset(const oe_asn1_t* asn1);

oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1, uint8_t* tag);

oe_result_t oe_asn1_get(
    oe_asn1_t* asn1,
    uint8_t* tag,
    const uint8_t** data,
    size_t* length);

oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1, oe_asn1_t* sequence);

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1, int* value);

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1, oe_oid_string_t* oid);

oe_result_t oe_asn1_get_octet_string(
    oe_asn1_t* asn1, 
    const uint8_t** data,
    size_t* length);

OE_EXTERNC_END

#endif /* _OE_ASN1_H */
