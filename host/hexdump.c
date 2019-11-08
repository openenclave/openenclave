// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>

void oe_hex_dump(const void* data_, size_t size)
{
    size_t i;
    const unsigned char* data = (const unsigned char*)data_;

    if (!data || !size)
        return;

    for (i = 0; i < size; i++)
    {
        printf("%02x", data[i]);
    }

    printf("\n");
}

char* oe_hex_string(
    char* str,
    size_t str_size,
    const void* data,
    size_t data_size)
{
    char* s = str;
    const uint8_t* p = (const uint8_t*)data;
    size_t n = data_size;

    if (!str || !data)
        return NULL;

    if (str_size < (2 * data_size + 1))
        return NULL;

    while (n--)
    {
        snprintf(s, 3, "%02x", *p);
        p++;
        s += 2;
    }

    *s = '\0';

    return str;
}
