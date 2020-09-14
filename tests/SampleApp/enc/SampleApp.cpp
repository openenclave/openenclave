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

#define TA_UUID                                            \
    { /* 25419627-14f6-4625-9329-cf5f10a57fea */           \
        0x25419627, 0x14f6, 0x4625,                        \
        {                                                  \
            0x93, 0x29, 0xcf, 0x5f, 0x10, 0xa5, 0x7f, 0xea \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1024 * 4096,
    256 * 4096,
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "SampleApp test");
