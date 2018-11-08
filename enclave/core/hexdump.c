// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>

/* Convert a nibble to an ASCII character: Example 0xF => 'F' */
OE_INLINE char _nibble_to_hex_char(uint8_t x)
{
    return (char)((x < 10) ? ('0' + (char)x) : ('A' + ((char)x - 10)));
}

/* Convert high nibble to a hex character */
OE_INLINE char _high_nibble_to_hex_char(uint8_t byte)
{
    return _nibble_to_hex_char(byte >> 4);
}

/* Convert low nibble to a hex character */
OE_INLINE char _low_nibble_to_hex_char(uint8_t byte)
{
    return _nibble_to_hex_char(byte & 0x0F);
}

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
        *s++ = _high_nibble_to_hex_char(*p);
        *s++ = _low_nibble_to_hex_char(*p);
        p++;
    }

    /* Zero-terminate the string */
    *s = '\0';

    return str;
}

#define CHUNK_SIZE 1024
void oe_hex_dump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;
    size_t n = size;
    char buf[2 * CHUNK_SIZE + 1];

    /* Return if nothing to print */
    if (!data || !size)
        return;

    /* Print N-sized chunks first to reduce OCALLS */
    while (n >= CHUNK_SIZE)
    {
        oe_hex_string(buf, sizeof(buf), p, CHUNK_SIZE);
        oe_host_printf("%s", buf);
        p += CHUNK_SIZE;
        n -= CHUNK_SIZE;
    }

    /* Print any remaining bytes */
    if (n)
    {
        oe_hex_string(buf, sizeof(buf), p, n);
        oe_host_printf("%s", buf);
    }

    oe_host_printf("\n");
}
