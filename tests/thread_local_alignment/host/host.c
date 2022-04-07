// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "alignment_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s enclave1 [enclave2 ...]\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    for (int ii = 1; ii < argc; ++ii)
    {
        enclave = NULL;
        printf("Testing %s\n", argv[ii]);
        fflush(stdout);

        if ((result = oe_create_alignment_enclave(
                 argv[ii], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
            oe_put_err(
                "oe_create_enclave() failed for %s: result=%u",
                argv[ii],
                result);

        result = enc_test_alignment(enclave);

        if (result != OE_OK)
            oe_put_err("alignment test failed for %s\n", argv[ii]);

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
        fflush(stdout);
    }

    printf("=== passed all tests (thread_local_alignment)\n");

    return 0;
}
