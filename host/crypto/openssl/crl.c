// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "crl.h"
#include <limits.h>
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/crypto/crl.h>
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <string.h>
#include <time.h>

/* Randomly generated magic number */
#define OE_CRL_MAGIC 0xe8c993b1cca24906

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/* Needed for compatibility with ssl1.1 */
static const ASN1_TIME* X509_CRL_get0_lastUpdate(const X509_CRL* crl)
{
    if (!crl->crl)
    {
        return NULL;
    }
    return crl->crl->lastUpdate;
}

static const ASN1_TIME* X509_CRL_get0_nextUpdate(const X509_CRL* crl)
{
    if (!crl->crl)
    {
        return NULL;
    }
    return crl->crl->nextUpdate;
}

#endif

OE_STATIC_ASSERT(sizeof(crl_t) <= sizeof(oe_crl_t));

OE_INLINE void _crl_init(crl_t* impl, X509_CRL* crl)
{
    impl->magic = OE_CRL_MAGIC;
    impl->crl = crl;
}

bool crl_is_valid(const crl_t* impl)
{
    return impl && (impl->magic == OE_CRL_MAGIC) && impl->crl;
}

OE_INLINE void _crl_free(crl_t* impl)
{
    X509_CRL_free(impl->crl);
    memset(impl, 0, sizeof(crl_t));
}

oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_size)
{
    oe_result_t result = OE_CRYPTO_ERROR;
    crl_t* impl = (crl_t*)crl;
    BIO* bio = NULL;
    X509_CRL* x509_crl = NULL;

    /* Clear the implementation */
    if (impl)
        memset(impl, 0, sizeof(crl_t));

    /* Check for invalid parameters */
    if (!der_data || !der_size || der_size > OE_INT_MAX || !crl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create a BIO for reading the DER-formatted data */
    if (!(bio = BIO_new_mem_buf(der_data, (int)der_size)))
        goto done;

    /* Read BIO into X509_CRL object */
    if (!(x509_crl = d2i_X509_CRL_bio(bio, NULL)))
        goto done;

    /* Initialize the implementation */
    _crl_init(impl, x509_crl);
    x509_crl = NULL;

    result = OE_OK;

done:

    if (x509_crl)
        X509_CRL_free(x509_crl);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_crl_free(oe_crl_t* crl)
{
    oe_result_t result = OE_UNEXPECTED;
    crl_t* impl = (crl_t*)crl;

    /* Check the parameter */
    if (!crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Free the CRL */
    _crl_free(impl);

    result = OE_OK;

done:
    return result;
}

// Parse a string into a oe_datetime_t: example: "May 30 10:23:42 2018 GMT".
// This format is specific to OpenSSL: produced by ASN1_TIME_print().
static oe_result_t _string_to_date(const char* str, oe_datetime_t* date)
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

static oe_result_t _asn1_time_to_date(
    const ASN1_TIME* time,
    oe_datetime_t* date)
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

    OE_CHECK(_string_to_date(mem->data, date));

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_crl_get_update_dates(
    const oe_crl_t* crl,
    oe_datetime_t* last,
    oe_datetime_t* next)
{
    oe_result_t result = OE_UNEXPECTED;
    const crl_t* impl = (const crl_t*)crl;

    if (last)
        memset(last, 0, sizeof(oe_datetime_t));

    if (next)
        memset(next, 0, sizeof(oe_datetime_t));

    if (!crl_is_valid(impl))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (last)
    {
        const ASN1_TIME* time;

        if (!(time = X509_CRL_get0_lastUpdate(impl->crl)))
            OE_RAISE(OE_CRYPTO_ERROR);

        OE_CHECK(_asn1_time_to_date(time, last));
    }

    if (next)
    {
        const ASN1_TIME* time;

        if (!(time = X509_CRL_get0_nextUpdate(impl->crl)))
            OE_RAISE(OE_CRYPTO_ERROR);

        OE_CHECK(_asn1_time_to_date(time, next));
    }

    result = OE_OK;

done:

    return result;
}
