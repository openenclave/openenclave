// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "SampleApp_t.h"

const char* ProtectedMessage = "Hello world from Enclave\n\0";

int secure_str_patching(const char* src, char* dst, size_t dst_length)
{
    const char* running_src = src;
    size_t running_length = dst_length;
    while (running_length > 0 && *running_src != '\0')
    {
        *dst = *running_src;
        running_length--;
        running_src++;
        dst++;
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
    int rval = -1;
    OE_TEST(unsecure_str_patching(&rval, src, dst, dst_length) == OE_OK);
    return rval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */
