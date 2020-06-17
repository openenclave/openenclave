// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CERT_INTERNAL_H
#define _OE_CERT_INTERNAL_H

#include "crypto/cert.h"

OE_EXTERNC_BEGIN

/**
 * Read a certificate from PEM format
 *
 * This function reads a certificate from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN CERT-----
 *     ...
 *     -----END CERT-----
 *
 * The caller is responsible for releasing the certificate by passing it to
 * oe_cert_free().
 *
 * @param cert initialized certificate handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK load was successful
 */
oe_result_t oe_cert_read_pem(
    oe_cert_t* cert,
    const void* pem_data,
    size_t pem_size);

OE_EXTERNC_END

#endif /* _OE_CERT_INTERNAL_H */
