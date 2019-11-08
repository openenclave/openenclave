// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/internal/tests.h>
#include <stdint.h>
#include <string.h>

static unsigned char to_num(char c)
{
    if (c >= '0' && c <= '9')
        return (unsigned char)(c - '0');

    if (c >= 'A' && c <= 'F')
        return (unsigned char)(10 + (c - 'A'));

    OE_TEST(c >= 'a' && c <= 'f');
    return (unsigned char)(10 + (c - 'a'));
}

void hex_to_buf(const char* str, uint8_t* buf, size_t bufsize)
{
    size_t strsz;
    OE_TEST(str != NULL && buf != NULL);

    strsz = strlen(str);
    OE_TEST(strsz % 2 == 0 && bufsize >= strsz / 2);

    for (size_t i = 0; i < strsz; i += 2)
    {
        unsigned char v =
            (unsigned char)(16 * to_num(str[i]) + to_num(str[i + 1]));
        buf[i / 2] = v;
    }
}
