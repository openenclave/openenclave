// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/hexdump.h>
#include <openenclave/enclave.h>

/* Convert a nibble to an ASCII character: Example 0xF => 'F' */
OE_INLINE char _NibbleToHexChar(uint8_t x)
{
    return (x < 10) ? ('0' + x) : ('A' + (x - 10));
}

/* Convert high nibble to a hex character */
OE_INLINE char _HighNibbleToHexChar(uint8_t byte)
{
    return _NibbleToHexChar(byte >> 4);
}

/* Convert low nibble to a hex character */
OE_INLINE char _LowNibbleToHexChar(uint8_t byte)
{
    return _NibbleToHexChar(byte & 0x0F);
}

char* OE_HexString(char* str, size_t strSize, const void* data, size_t dataSize)
{
    /* Check parameters */
    if (!str || !data || (strSize < (2 * dataSize + 1)))
        return NULL;

    char* s = str;
    const uint8_t* p = (const uint8_t*)data;
    size_t n = dataSize;

    /* For each byte in data buffer */
    while (n--)
    {
        *s++ = _HighNibbleToHexChar(*p);
        *s++ = _LowNibbleToHexChar(*p);
        p++;
    }

    /* Zero-terminate the string */
    *s = '\0';

    return str;
}

void OE_HexDump(const void* data, size_t size)
{
    const uint8_t* p = (const uint8_t*)data;
    size_t n = size;
    const size_t chunkSize = 1024;
    char buf[2 * chunkSize + 1];

    /* Return if nothing to print */
    if (!data || !size)
        return;

    /* Print N-sized chunks first to reduce OCALLS */
    while (n >= chunkSize)
    {
        OE_HexString(buf, sizeof(buf), p, chunkSize);
        OE_HostPrintf("%s", buf);
        p += chunkSize;
        n -= chunkSize;
    }

    /* Print any remaining bytes */
    if (n)
    {
        OE_HexString(buf, sizeof(buf), p, n);
        OE_HostPrintf("%s", buf);
    }

    OE_HostPrintf("\n");
}
