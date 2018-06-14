// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "../args.h"

using namespace std;

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    printf("==== %s\n", argv[0]);

    /* Check argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Create an enclave from the file given by argv[1] */
    {
        const uint64_t flags = oe_get_create_flags();

        if ((result = oe_create_enclave(
                 argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
        {
            cerr << "oe_create_enclave(): result=" << result << endl;
            exit(1);
        }
    }

    /* Call into Hello() function in the enclave */
    {
        Args args;

        size_t data[] = {2, 1, 4, 5, 3, 10, 6, 7, 8, 9};
        size_t size = OE_COUNTOF(data);

        args.data = data;
        args.size = size;

        if ((result = oe_call_enclave(enclave, "Sort", &args)) != OE_OK)
        {
            cerr << "oe_call_enclave(): result=" << result << endl;
            exit(1);
        }

        for (size_t i = 0; i < size; i++)
        {
            printf("%zu ", data[i]);
        }

        printf("\n\n");
    }

    /* Terminate the enclave */
    oe_terminate_enclave(enclave);

    return 0;
}
