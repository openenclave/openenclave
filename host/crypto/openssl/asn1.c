// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../common/asn1.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/datetime.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/asn1.h>
#include <openssl/pem.h>
#include <string.h>

#include "asn1.h"

OE_STATIC_ASSERT(V_ASN1_CONSTRUCTED == OE_ASN1_TAG_CONSTRUCTED);
OE_STATIC_ASSERT(V_ASN1_SEQUENCE == OE_ASN1_TAG_SEQUENCE);
OE_STATIC_ASSERT(V_ASN1_INTEGER == OE_ASN1_TAG_INTEGER);
OE_STATIC_ASSERT(V_ASN1_OBJECT == OE_ASN1_TAG_OID);
OE_STATIC_ASSERT(V_ASN1_OCTET_STRING == OE_ASN1_TAG_OCTET_STRING);

oe_result_t oe_asn1_get_raw(
    oe_asn1_t* asn1,
    oe_asn1_tag_t* tag,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;

    if (data)
        *data = NULL;

    if (length)
        *length = 0;

    if (!oe_asn1_is_valid(asn1) || !tag || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        long tmp_length = 0;
        int tmp_tag = 0;
        int tmp_class = 0;

        int rc = ASN1_get_object(
            &asn1->ptr,
            &tmp_length,
            &tmp_tag,
            &tmp_class,
            (long)oe_asn1_remaining(asn1));

        if (rc != V_ASN1_CONSTRUCTED && rc != 0)
            OE_RAISE(OE_FAILURE);

        *tag = tmp_tag;
        *data = asn1->ptr;
        *length = (size_t)tmp_length;

        asn1->ptr += *length;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_sequence(oe_asn1_t* asn1, oe_asn1_t* sequence)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_asn1_tag_t tag;
    const uint8_t* data;
    size_t length;

    if (sequence)
        memset(sequence, 0, sizeof(oe_asn1_t));

    if (!oe_asn1_is_valid(asn1) || !sequence)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_raw(asn1, &tag, &data, &length));

    if (tag != OE_ASN1_TAG_SEQUENCE)
        OE_RAISE(OE_FAILURE);

    oe_asn1_init(sequence, data, length);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_integer(oe_asn1_t* asn1, int* value)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_asn1_tag_t tag;
    const uint8_t* data;
    size_t length;

    if (value)
        *value = 0;

    if (!oe_asn1_is_valid(asn1) || !value)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_raw(asn1, &tag, &data, &length));

    if (tag != OE_ASN1_TAG_INTEGER)
        OE_RAISE(OE_FAILURE);

    /* Extract the varying-length integer one byte at a time. */
    while (length--)
        *value = (*value << 8) | *data++;

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_get_oid(oe_asn1_t* asn1, oe_oid_string_t* oid)
{
    oe_result_t result = OE_UNEXPECTED;
    ASN1_OBJECT* obj = NULL;

    if (oid)
        memset(oid, 0, sizeof(oe_oid_string_t));

    if (!oe_asn1_is_valid(asn1) || !oid)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the OID and covert it to string */
    {
        const unsigned char* ptr = asn1->ptr;

        /* Convert OID to an ASN1 object */
        if (!(obj = d2i_ASN1_OBJECT(&obj, &ptr, (long)oe_asn1_remaining(asn1))))
            OE_RAISE(OE_CRYPTO_ERROR);

        /* Convert OID to string format */
        if (!OBJ_obj2txt(oid->buf, sizeof(oe_oid_string_t), obj, 1))
            OE_RAISE(OE_CRYPTO_ERROR);

        asn1->ptr = ptr;
    }

    result = OE_OK;

done:

    if (obj)
        ASN1_OBJECT_free(obj);

    return result;
}

oe_result_t oe_asn1_get_octet_string(
    oe_asn1_t* asn1,
    const uint8_t** data,
    size_t* length)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_asn1_tag_t tag;

    if (data)
        *data = NULL;

    if (length)
        *length = 0;

    if (!oe_asn1_is_valid(asn1) || !data || !length)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_asn1_get_raw(asn1, &tag, data, length));

    if (tag != OE_ASN1_TAG_OCTET_STRING)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_string_to_date(const char* str, oe_datetime_t* date)
{
    oe_result_t result = OE_UNEXPECTED;
    char month[4];

    memset(date, 0, sizeof(oe_datetime_t));

    /* Convert the string to oe_datetime_t struct */
    if (sscanf(
            str,
            "%3s %02u %02u:%02u:%02u %04u",
            month,
            &date->day,
            &date->hours,
            &date->minutes,
            &date->seconds,
            &date->year) != 6)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Convert the month string to integer */
    {
        static const char* _month[] = {"Jan",
                                       "Feb",
                                       "Mar",
                                       "Apr",
                                       "May",
                                       "Jun",
                                       "Jul",
                                       "Aug",
                                       "Sep",
                                       "Oct",
                                       "Nov",
                                       "Dec"};

        date->month = UINT_MAX;

        for (uint32_t i = 0; i < OE_COUNTOF(_month); i++)
        {
            if (strncmp(month, _month[i], 3) == 0)
            {
                date->month = i + 1;
                break;
            }
        }

        if (date->month == UINT_MAX)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_asn1_time_to_date(const ASN1_TIME* time, oe_datetime_t* date)
{
    oe_result_t result = OE_UNEXPECTED;
    struct tm;
    BIO* bio = NULL;
    BUF_MEM* mem;
    const char null_terminator = '\0';

    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!ASN1_TIME_print(bio, time))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!BIO_get_mem_ptr(bio, &mem))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (BIO_write(bio, &null_terminator, sizeof(null_terminator)) <= 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    OE_CHECK(oe_asn1_string_to_date(mem->data, date));

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}