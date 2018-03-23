// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <stdio.h>

void OE_HexDump(const void* data_, size_t size)
{
    size_t i;
    const unsigned char* data = (const unsigned char*)data_;

    if (!data || !size)
        return;

    for (i = 0; i < size; i++)
    {
        printf("%02X", data[i]);
    }

    printf("\n");
}

char* OE_HexString(
    char* str, 
    size_t strSize, 
    const void* data, 
    size_t dataSize)
{
    if (!str || !data)
        return NULL;

    if (strSize < (2 * dataSize + 1))
        return NULL;

    for (size_t i = 0; i < dataSize; i++)
    {
        snprintf(&str[i*2], 3, "%02X", ((const uint8_t*)data)[i]);
    }

    str[strSize - 1] = '\0';

    return str;
}
