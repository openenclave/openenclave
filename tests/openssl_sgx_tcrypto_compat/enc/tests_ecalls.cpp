// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <stdlib.h>
#include "include_openssl.h"
#include "openssl/crypto.h"
#include "openssl_schema.h"
#include "openssl_sgx_tcrypto_compat_t.h"

extern int common_digest_tests(openssl_api_param* parameter);

int ecall_schema_run_digest_tests(openssl_api_param* parameter)
{
    return common_digest_tests(parameter);
}
