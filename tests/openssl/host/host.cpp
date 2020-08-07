// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_u.h"

#ifdef __linux__
extern char** environ;
char** _environ = environ; // _environ is defined by stdlib.h on Windows.
#endif

void test(oe_enclave_t* enclave, int argc, char** argv)
{
    int ret = 1;
    char** env = _environ;

    oe_result_t result = enc_test(enclave, &ret, argc, argv, env);
    OE_TEST(result == OE_OK);

    if (ret == 0)
    {
        printf("PASSED: %s\n", argv[0]);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", argv[0], ret);
        abort();
    }
}

static int _get_opt(
    int& argc,
    char* argv[],
    const char* name,
    const char** arg = NULL)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (!arg)
            {
                memmove(
                    (void*)&argv[i],
                    &argv[i + 1],
                    static_cast<size_t>(argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
            {
                return -1;
            }

            *arg = argv[i + 1];
            memmove(
                (char**)&argv[i],
                &argv[i + 2],
                static_cast<size_t>(argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

int main(int argc, char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    /* Check for the --sim option. */
    if (_get_opt(argc, argv, "--simulate") == 1)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }
    else
    {
        flags = oe_get_create_flags();
    }

    /* Check the argument count. */
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE testname\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s %s\n", argv[0], argv[1], argv[2]);

    /* Create the enclave. */
    if ((result = oe_create_openssl_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    /*
     * Ignore the first two arguments (i.e., host and enclave) and
     * invoke enc_test().
     */
    test(enclave, argc - 2, (char**)(&argv[2]));

    /* Shutdown the enclave. */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("\n");

    return 0;
}
