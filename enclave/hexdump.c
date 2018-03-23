// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/hexdump.h>

/* Convert a nibble to an ASCII character: Example 0xF => 'F' */
OE_INLINE char _NibbleToHexChar(uint8_t x)
{
    return (x < 10) ? ('0' + x) : ('A' + (x - 10));
}

/* Convert a byte to an ASCII hex string. Example: 0x3F => "3F" */
static void _ByteToHexString(uint8_t byte, char buf[3])
{
    /* Convert high nibble to character */
    buf[0] = _NibbleToHexChar(byte >> 4);

    /* Convert low nibble to character */
    buf[1] = _NibbleToHexChar(byte & 0x0F);

    /* Zero-terminate the string */
    buf[2] = '\0';
}

void OE_HexDump(const void* data, size_t size)
{
    size_t i;
    const uint8_t* p = (const uint8_t*)data;

    if (!data || !size)
        return;

    for (i = 0; i < size; i++)
    {
        char buf[3];
        _ByteToHexString(p[i], buf);
        OE_HostPrintf("%s", buf);
    }

    OE_HostPrintf("\n");
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
        _ByteToHexString(((const uint8_t*)data)[i], &str[i*2]);

    str[strSize - 1] = '\0';

    return str;
}
