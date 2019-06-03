// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file asn1.h
 */

#ifndef _OE_ASN1_INTERNAL_H
#define _OE_ASN1_INTERNAL_H

#include "crypto/asn1.h"

OE_EXTERNC_BEGIN

/**
 * Gets the tag at the current position of the ASN.1 input stream without
 * changing the current position.
 *
 * @param asn1[in] the ASN.1 input stream.
 * @param tag[out] the tag at the current position in the input stream.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_peek_tag(const oe_asn1_t* asn1, oe_asn1_tag_t* tag);

/**
 * Gets the next ASN.1 element from the ASN.1 input stream.
 *
 * This function gets the next ASN.1 element from the ASN.1 input stream and
 * advances the current position just beyond that element. All elements have
 * the following format.
 *
 *     ```
 *     [TAG] [LENGTH] [BYTES]
 *     ```
 *
 * @param asn1[in,out] the ASN.1 input stream.
 * @param tag[out] the element's tag
 * @param data[out] the element's data
 * @param length[out] the element's length
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_get_raw(
    oe_asn1_t* asn1,
    oe_asn1_tag_t* tag,
    const uint8_t** data,
    size_t* length);

/**
 * Gets an integer element from the ASN.1 input stream.
 *
 * This function gets an integer element from the ASN.1 input stream and
 * advances the current position just beyond that element.
 *
 * @param asn1[in,out] the ASN.1 input stream.
 * @param value[out] the value of the integer element.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1, int* value);

/**
 * Gets an OID element from the ASN.1 input stream.
 *
 * This function gets an OID element from the ASN.1 input stream and
 * advances the current position just beyond that element.
 *
 * @param asn1[in,out] the ASN.1 input stream.
 * @param oid[out] the value of that element as an OID string.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1, oe_oid_string_t* oid);

/**
 * Gets an octet string element from the ASN.1 input stream.
 *
 * This function gets an octet string element from the ASN.1 input stream and
 * advances the current position just beyond that element.
 *
 * @param asn1[in,out] the ASN.1 input stream.
 * @param data[out] a pointer to the octet string.
 * @param length[out] the length of the octet string.
 *
 * @return OE_OK success
 * @return OE_INVALID_PARAMETER a parameter is invalid
 * @return OE_FAILURE general failure
 */
oe_result_t oe_asn1_get_octet_string(
    oe_asn1_t* asn1,
    const uint8_t** data,
    size_t* length);

OE_EXTERNC_END

#endif /* _OE_ASN1_INTERNAL_H */
