#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include <stdio.h>

void __OE_HexDump(const void* data_, size_t size)
{
    size_t i;
    const unsigned char* data = (const unsigned char*)data_;

    if (!data || !size)
        return;

    for (i = 0; i < size; i++)
    {
        printf("%02x", data[i]);

#if 0
        if ((i + 1) % 16 == 0)
            printf("\n");
        else
            printf(" ");
#endif
    }

    printf("\n");
}
