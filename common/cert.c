// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/asn1.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/outbuf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/print.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/enclavelibc.h>
#define memset oe_memset
#define printf oe_host_printf
#define memcmp oe_memcmp
#define memcpy oe_memcpy
#else
#include <stdio.h>
#include <string.h>
#endif

static oe_result_t _find_url(
    const uint8_t* data,
    size_t size,
    const char** url,
    size_t* url_len)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* p = data;
    size_t remaining = size;

    /* Search for "https:" preceded by the length of the URL */
    while (remaining)
    {
        const char PATTERN[] = "https:";

        if (memcmp(p, PATTERN, sizeof(PATTERN) - 1) == 0)
        {
            /* Fail if string begins with the pattern */
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

oe_result_t oe_get_crl_distribution_points(
    const oe_cert_t* cert,
    const char*** urls,
    size_t* num_urls,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t size = 0;
    static const char _OID[] = "2.5.29.31";
    oe_outbuf_t outbuf;

    if (urls)
        *urls = NULL;

    if (num_urls)
        *num_urls = 0;

    if (!cert || !urls || !num_urls || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_outbuf_start(&outbuf, buffer, buffer_size, sizeof(void*)));

    /* Determine the size of the extension */
    if (oe_cert_find_extension(cert, _OID, NULL, &size) != OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    /* Find all the CRL distribution points in this extension */
    {
        uint8_t data[size];
        oe_asn1_t asn1;

        /* Find the extension */
        size = sizeof(data);
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

        /* Leave space for urls[] array */
        oe_outbuf_append(&outbuf, NULL, sizeof(char*) * (*num_urls));

        /* Set the pointer to the urls[] array */
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
                const char* addr;
                const size_t addr_size = sizeof(addr);

                OE_CHECK(oe_asn1_get_sequence(&seq, &crldp));
                OE_CHECK(_find_url(crldp.data, crldp.length, &url, &url_len));

                if ((addr = (const char*)oe_outbuf_end(&outbuf)))
                {
                    /* Append the next urls[i] address */
                    oe_outbuf_set(&outbuf, i * addr_size, &addr, addr_size);
                }

                /* Append the URL */
                oe_outbuf_append(&outbuf, url, url_len);

                /* Append null terminator */
                oe_outbuf_append(&outbuf, NULL, 1);
            }
        }
    }

    OE_CHECK(oe_outbuf_finish(&outbuf, buffer_size));

    result = OE_OK;

done:
    return result;
}
