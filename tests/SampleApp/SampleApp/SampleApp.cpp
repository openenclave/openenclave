// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

const char* ProtectedMessage = "Hello world from Enclave\n\0";

int HostUnsecureStrPatching(const char* src, char* dst, int dst_length);

int SecureStrPatching(const char* src, char* dst, int dst_length)
{
    if (!oe_is_outside_enclave(dst, (size_t)dst_length))
    {
        return -1;
    }
    if (!oe_is_outside_enclave(src, 1))
    {
        return -1;
    }
    const char* running_src = src;
    int running_length = dst_length;
    while (running_length > 0 && *running_src != '\0')
    {
        *dst = *running_src;
        running_length--;
        running_src++;
        dst++;
        if (!oe_is_outside_enclave(running_src, 1))
        {
            return -1;
        }
    }
    const char* ptr = ProtectedMessage;
    while (running_length > 0 && *ptr != '\0')
    {
        *dst = *ptr;
        running_length--;
        ptr++;
        dst++;
    }
    if (running_length < 1)
    {
        return -1;
    }
    *dst = '\0';
    return HostUnsecureStrPatching(src, dst, dst_length);
}
