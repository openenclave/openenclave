// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/trace.h>
#include "intstr.h"

char* oe_hex_string(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size)
{
    /* Check parameters */
    if (!str || !data || (str_size < (2 * data_size + 1)))
        return NULL;

    char* s = str;
    const uint8_t* p = (const uint8_t*)data;
    size_t n = data_size;

    /* For each byte in data buffer */
    while (n--)
    {
        *s++ = oe_get_hex_char(*p, 1);
        *s++ = oe_get_hex_char(*p, 0);
        p++;
    }

    /* Zero-terminate the string */
    *s = '\0';

    return str;
}

void oe_hex_dump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;
    size_t n = size;
    const size_t chunk_size = 1024;
    char buf[2 * chunk_size + 1];

    /* Return if nothing to print */
    if (!data || !size)
        return;

    /* Print N-sized chunks first to reduce OCALLS */
    while (n >= chunk_size)
    {
        oe_hex_string(buf, sizeof(buf), p, chunk_size);
        OE_TRACE_INFO("%s = ", buf);
        p += chunk_size;
        n -= chunk_size;
    }

    /* Print any remaining bytes */
    if (n)
    {
        oe_hex_string(buf, sizeof(buf), p, n);
        OE_TRACE_INFO("%s = ", buf);
    }
    OE_TRACE_INFO("\n");
}
