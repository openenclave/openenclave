// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "sgx_zerobase_t.h"

const char* protected_message = "Hello world from Enclave\n\0";

int secure_string_patching(
    const char* source,
    char* output,
    size_t output_length)
{
    const char* running_source = source;
    size_t running_length = output_length;
    while (running_length > 0 && *running_source != '\0')
    {
        *output = *running_source;
        running_length--;
        running_source++;
        output++;
    }
    const char* ptr = protected_message;
    while (running_length > 0 && *ptr != '\0')
    {
        *output = *ptr;
        running_length--;
        ptr++;
        output++;
    }
    if (running_length < 1)
    {
        return -1;
    }
    *output = '\0';
    int rval = -1;
    OE_TEST(
        unsecure_string_patching(&rval, source, output, output_length) ==
        OE_OK);
    return rval;
}

OE_SET_ENCLAVE_SGX2(
    1,       /* ProductID */
    1,       /* SecurityVersion */
    {0},     /* ExtendedProductID */
    {0},     /* FamilyID */
    true,    /* Debug */
    false,   /* CapturePFGPExceptions */
    false,   /* RequireKSS */
    true,    /* CreateZeroBaseEnclave */
    0x21000, /* StartAddress */
    1024,    /* NumHeapPages */
    1024,    /* NumStackPages */
    4);      /* NumTCS */
