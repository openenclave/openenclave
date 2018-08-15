// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    int ret = 0;
    oe_enclave_t* enclave = NULL;
    Args args;
    uint64_t flags = 0;
 
    printf("Host: entered main() with argv[0]= %s\n", argv[0]);

    /* Check argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s enclave_image_path\n", argv[0]);
        exit(1);
    }

    /* Create an enclave from the file given by argv[1] */
    printf("Host: created an enclave\n");
    flags = oe_get_create_flags();
    if ((result = oe_create_enclave(
                   argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
    {
        fprintf(stderr, "oe_create_enclave(): result=%u", result);
        exit(1);
    }
   

    /* Call into Enclave_HelloWorld function in the enclave */
    memset(&args, 0, sizeof(args));
    args.ret = -1;

    printf("Host: called enclave\'s \"Enclave_HelloWorld\"\n");
    if ((result = oe_call_enclave(enclave, "Enclave_HelloWorld", &args)) != OE_OK)
    {
         fprintf(stderr, "failed: result=%u", result);
	 ret = 1;
	 goto cleanup;
    }

    if (args.ret != 0)
    {
        fprintf(stderr, "ECALL failed args.result=%d", args.ret);
        ret = 1;
    }

cleanup:

    free((char*)args.in);
    free((char*)args.out);
    /* Terminate the enclave */
    oe_terminate_enclave(enclave);
    printf("Host: teriminated the enclave\n");

   return ret;
}


