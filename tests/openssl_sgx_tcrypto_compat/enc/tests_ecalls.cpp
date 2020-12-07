// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include "include_openssl.h"
#include "openssl/crypto.h"
#include "openssl_schema.h"
#include "openssl_sgx_tcrypto_compat_t.h"

extern int common_digest_tests(openssl_api_param* parameter);
void ecall_set_rdrand_engine()
{
    ENGINE* eng = nullptr;

    /* Initialize and opt-in the RDRAND engine. */
    ENGINE_load_rdrand();
    eng = ENGINE_by_id("rdrand");
    if (!eng)
    {
        goto done;
    }

    if (!ENGINE_init(eng))
    {
        goto done;
    }

    if (!ENGINE_set_default(eng, ENGINE_METHOD_RAND))
    {
        goto done;
    }

done:

    /* cleanup to avoid memory leak. */
    ENGINE_finish(eng);
    ENGINE_free(eng);
    ENGINE_cleanup();

    return;
}

int ecall_schema_run_digest_tests(openssl_api_param* parameter)
{
    return common_digest_tests(parameter);
}
