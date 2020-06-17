// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CRL_H
#define _OE_CRL_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/datetime.h>

OE_EXTERNC_BEGIN

typedef struct _oe_crl
{
    /* Internal private implementation */
    uint64_t impl[4];
} oe_crl_t;

/**
 * Read a certificate revocation list (CRL) from DER format.
 *
 * The caller is responsible for releasing the certificate by passing it to
 * oe_crl_free().
 *
 * @param crl initialized certificate handle upon return
 * @param der_data zero-terminated DER data.
 * @param der_size size of the DER data
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_crl_read_der(
    oe_crl_t* crl,
    const uint8_t* der_data,
    size_t der_size);

/**
 * Read a certificate revocation list (CRL) from PEM format.
 *
 * The caller is responsible for releasing the certificate by passing it to
 * oe_crl_free().
 *
 * @param crl initialized certificate handle upon return
 * @param der_data zero-terminated PEM data.
 * @param der_size size of the PEM data
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_crl_read_pem(
    oe_crl_t* crl,
    const uint8_t* pem_data,
    size_t pem_size);

/**
 * Releases a certificate revocation list (CRL)
 *
 * @param crl handle of the CRL being released
 *
 * @return OE_OK the CRL was successfully released
 */
oe_result_t oe_crl_free(oe_crl_t* crl);

/**
 * Obtains the **last** and **next** update dates for the given CRL.
 *
 * This function obtains the **last** and the **next** update dates for the
 * given CRL. The **last** date specifies when this CRL was last updated. The
 * **next** date specifies when a newer version of the CRL will be available
 * (after which this CRL should be considered invalid).
 *
 * @param crl the handle of a CRL.
 * @param last the date when the CRL was last updated (may be null).
 * @param next the date at which this CRL should be considered invalid
 *        (may be null).
 */
oe_result_t oe_crl_get_update_dates(
    const oe_crl_t* crl,
    oe_datetime_t* last,
    oe_datetime_t* next);

OE_EXTERNC_END

#endif /* _OE_CRL_H */
