// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_CRYPTO_ASN1_OPENSSL_H
#define _OE_HOST_CRYPTO_ASN1_OPENSSL_H

#include <openenclave/internal/datetime.h>
#include <openenclave/internal/result.h>
#include <openssl/asn1.h>

/**
 * Parse a string into a oe_datetime_t: example: "May 30 10:23:42 2018 GMT".
 * This format is specific to OpenSSL: produced by ASN1_TIME_print().
 *
 * @param str[in] string to parse into a oe_datetime_t
 * @param date[out] output datetime.
 */
oe_result_t oe_asn1_string_to_date(const char* str, oe_datetime_t* date);

/**
 * Convert an ASN1_TIME in openSSL format ta a oe_datetime_t.
 *
 * @param time[in] The time to convert.
 * @param date[out] The output datetime.
 */
oe_result_t oe_asn1_time_to_date(const ASN1_TIME* time, oe_datetime_t* date);

#endif /* _OE_HOST_CRYPTO_ASN1_OPENSSL_H */
