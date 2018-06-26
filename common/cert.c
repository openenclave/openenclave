// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/cert.h>
#include <openenclave/internal/asn1.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#ifdef OE_BUILD_ENCLAVE
# include <openenclave/internal/enclavelibc.h>
# define memset oe_memset
# define memcmp oe_memcmp
# define memcpy oe_memcpy
#else
# include <string.h>
#endif

static oe_result_t _find_url(
    const uint8_t* data, 
    size_t size,
    const char** url, 
    size_t* url_len)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* p = data;
    size_t r = size;

    /* Search for "https:" preceded by the length of the URL */
    while (r)
    {
        const char PATTERN[] = "https:";

        if (memcmp(p, PATTERN, sizeof(PATTERN)-1) == 0)
        {
            /* Fail if string begins with the pattern */
            if (p == data)
                OE_RAISE(OE_FAILURE);

            /* Get the length which immediately precedes the pattern */
            uint8_t len = p[-1];

            /* Fail if length excedes bytes remaining in the buffer */
            if (len > r)
                OE_RAISE(OE_OUT_OF_BOUNDS);

            /* Search URL for bad characters */
            for (size_t i = 0; i < len; i++)
            {
                if (!(p[i] >= ' ' && p[i] <= '~'))
                    OE_RAISE(OE_FAILURE);
            }

            *url = (char*)p;
            *url_len = len;
            result = OE_OK;
            goto done;
        }

        r--;
        p++;
    }

    result = OE_NOT_FOUND;

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
    const char OID[] = "2.5.29.31";
    size_t offset = 0;

    if (urls)
        *urls = NULL;

    if (num_urls)
        *num_urls = 0;

    if (!cert || !urls || !num_urls || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The buffer must be aligned on an 8-byte boundary */
    if (buffer != (uint8_t*)oe_round_up_to_multiple((uint64_t)buffer, 8))
        OE_RAISE(OE_BAD_ALIGNMENT);

    /* Determine the size of the extension */
    if (oe_cert_find_extension(cert, OID, NULL, &size) != OE_BUFFER_TOO_SMALL)
        OE_RAISE(OE_FAILURE);

    /* Find all the CRL distribution points in this extension */
    {
        uint8_t data[size];
        oe_asn1_t asn1;
        oe_asn1_t seq;

        /* Find the extension */
        size = sizeof(data);
        OE_CHECK(oe_cert_find_extension(cert, OID, data, &size));

        /* Determine the number of URLs */
        {
            OE_CHECK(oe_asn1_init(&asn1, data, size));
            OE_CHECK(oe_asn1_get_sequence(&asn1, &seq));

            while (oe_asn1_offset(&seq) < oe_asn1_length(&seq))
            {
                oe_asn1_t crldp;
                OE_CHECK(oe_asn1_get_sequence(&seq, &crldp));
                (*num_urls)++;
            }
        }

        /* Leave space for urls[] array */
        offset += sizeof(char*) * (*num_urls);

        /* Only set if buffer is big enough for urls[] array */
        if (offset <= *buffer_size)
            *urls = (const char**)buffer;

        /* Process all the CRL distribution points */
        {
            size_t index = 0;

            OE_CHECK(oe_asn1_init(&asn1, data, size));
            OE_CHECK(oe_asn1_get_sequence(&asn1, &seq));

            /* While there are more CRL distribution points */
            while (oe_asn1_offset(&seq) < oe_asn1_length(&seq))
            {
                oe_asn1_t crldp;
                const char* url;
                size_t url_len;

                OE_CHECK(oe_asn1_get_sequence(&seq, &crldp));

                OE_CHECK(_find_url(
                    oe_asn1_data(&crldp), 
                    oe_asn1_length(&crldp),
                    &url,
                    &url_len));

                if (buffer && (offset + url_len + 1) <= (*buffer_size))
                {
                    uint8_t* ptr = buffer + offset;

                    memcpy(ptr, url, url_len);
                    ptr[url_len] = '\0';

                    if (*urls)
                        (*urls)[index++] = (char*)ptr;
                }

                offset += url_len + 1;
            }
        }
    }

    if (offset < *buffer_size)
    {
        *buffer_size = offset;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    *buffer_size = offset;

    result = OE_OK;

done:
    return result;
}
