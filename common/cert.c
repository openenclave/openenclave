// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/crypto/cert.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "common.h"

/* oe_get_crl_distribution_points is shared between host OpenSSL and
 * enclave mbedTLS implementations. Windows host uses a different BCrypt
 * implementation in host/crypto/bcrypt/cert.c. */
#if defined(__linux__)
#include <openenclave/internal/asn1.h>

static oe_result_t _find_url(
    const uint8_t* data,
    size_t size,
    const char** url,
    size_t* url_len)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* p = data;
    size_t remaining = size;
    const char pattern[] = "http";
    const size_t pattern_length = sizeof(pattern) - 1;

    /* Search for "http" preceded by the length of the URL */
    while (remaining >= pattern_length)
    {
        if (memcmp(p, pattern, pattern_length) == 0)
        {
            /* Fail if data begins with the pattern */
            if (p == data)
                OE_RAISE(OE_FAILURE);

            /* Get the length which immediately precedes the pattern */
            uint8_t len = p[-1];

            /* Fail if length exceeds bytes remaining in the buffer */
            if (len > remaining)
                OE_RAISE(OE_FAILURE);

            *url = (char*)p;
            *url_len = len;
            result = OE_OK;
            goto done;
        }

        remaining--;
        p++;
    }

    result = OE_FAILURE;

done:
    return result;
}

// Append up to 'n' bytes of string 's' to the buffer at the given offset. If
// less than 'n' bytes remain, then ignore the excess bytes of string 's'.
// Update the offset, which may legally exceed the buffer size. Upon return,
// the offset indicates how many bytes would be required to hold the data.
static oe_result_t _append(
    void* buffer,
    size_t size,
    size_t* offset,
    const void* s,
    size_t n)
{
    oe_result_t result = OE_UNEXPECTED;
    /* If any space remaining in the buffer: */
    if (*offset < size)
    {
        const size_t remaining = size - *offset;
        const size_t m = (remaining < n) ? remaining : n;
        void* ptr = (uint8_t*)buffer + *offset;

        if (s)
        {
            // Copy 'm' bytes from string 's'.
            OE_CHECK(oe_memcpy_s(ptr, remaining, s, m));
        }
        else
        {
            // Fill with 'm' zero bytes.
            oe_secure_zero_fill(ptr, m);
        }
    }

    *offset += n;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_get_crl_distribution_points(
    const oe_cert_t* cert,
    const char*** urls,
    size_t* num_urls,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t size = 0;
    size_t offset = 0;
    static const char _OID[] = "2.5.29.31";
    uint8_t* data = NULL;

    if (urls)
        *urls = NULL;

    if (num_urls)
        *num_urls = 0;

    if (!cert || !urls || !num_urls || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is not aligned properly to hold an array of pointers */
    if (oe_align_pointer(buffer, sizeof(void*)) != buffer)
        OE_RAISE(OE_BAD_ALIGNMENT);

    /* Determine the size of the extension */
    if (oe_cert_find_extension(cert, _OID, NULL, &size) != OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    /* Find all the CRL distribution points in this extension */
    {
        oe_asn1_t asn1;
        size_t urls_bytes;

        /* Find the extension */
        data = (uint8_t*)oe_malloc(size);
        if (!data)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(oe_cert_find_extension(cert, _OID, data, &size));

        /* Determine the number of URLs */
        {
            oe_asn1_t seq;

            oe_asn1_init(&asn1, data, size);
            OE_CHECK(oe_asn1_get_sequence(&asn1, &seq));

            while (oe_asn1_more(&seq))
            {
                oe_asn1_t crldp;
                OE_CHECK(oe_asn1_get_sequence(&seq, &crldp));
                (*num_urls)++;
            }
        }

        /* Determine the number of bytes needed by the urls[] array */
        urls_bytes = sizeof(char*) * (*num_urls);

        /* Leave space for urls[] array */
        OE_CHECK(_append(buffer, *buffer_size, &offset, NULL, urls_bytes));

        /* Set the pointer to the urls[] array if enough space */
        if (buffer && urls_bytes <= *buffer_size)
            *urls = (const char**)buffer;

        /* Process all the CRL distribution points */
        {
            oe_asn1_t seq;

            oe_asn1_init(&asn1, data, size);
            OE_CHECK(oe_asn1_get_sequence(&asn1, &seq));

            /* While there are more CRL distribution points */
            for (size_t i = 0; oe_asn1_more(&seq); i++)
            {
                oe_asn1_t crldp;
                const char* url;
                size_t url_len;

                OE_CHECK(oe_asn1_get_sequence(&seq, &crldp));
                OE_CHECK(_find_url(crldp.data, crldp.length, &url, &url_len));

                /* Append current buffer position to the urls[] array */
                if (*urls)
                {
                    // The address could point beyond end of buffer, but that is
                    // fine since an OE_BUFFER_TOO_SMALL error is raised below.
                    (*urls)[i] = (const char*)(buffer + offset);
                }

                /* Append the URL */
                OE_CHECK(_append(buffer, *buffer_size, &offset, url, url_len));

                /* Append null terminator */
                OE_CHECK(
                    _append(buffer, *buffer_size, &offset, NULL, sizeof(char)));
            }
        }
    }

    if (offset > *buffer_size)
    {
        *buffer_size = offset;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    *buffer_size = offset;
    result = OE_OK;

done:
    if (data)
        oe_free(data);

    return result;
}
#endif

oe_result_t oe_cert_chain_get_root_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t length = 0;

    OE_CHECK(oe_cert_chain_get_length(chain, &length));
    if (length == 0)
        OE_RAISE(OE_NOT_FOUND);
    OE_CHECK(oe_cert_chain_get_cert(chain, length - 1, cert));
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_cert_chain_get_leaf_cert(
    const oe_cert_chain_t* chain,
    oe_cert_t* cert)
{
    oe_result_t result = oe_cert_chain_get_cert(chain, 0, cert);
    if (result == OE_OUT_OF_BOUNDS)
        result = OE_NOT_FOUND;
    return result;
}

oe_result_t oe_cert_write_public_key_pem(
    const oe_cert_t* cert,
    uint8_t* pem_data,
    size_t* pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_ec_public_key_t ec_public_key;
    oe_rsa_public_key_t rsa_public_key;

    if (oe_cert_get_ec_public_key(cert, &ec_public_key) == OE_OK)
    {
        OE_CHECK(
            oe_ec_public_key_write_pem(&ec_public_key, pem_data, pem_size));
        OE_CHECK(oe_ec_public_key_free(&ec_public_key));
    }
    else if (oe_cert_get_rsa_public_key(cert, &rsa_public_key) == OE_OK)
    {
        OE_CHECK(
            oe_rsa_public_key_write_pem(&rsa_public_key, pem_data, pem_size));
        OE_CHECK(oe_rsa_public_key_free(&rsa_public_key));
    }
    result = OE_OK;

done:

    return result;
}