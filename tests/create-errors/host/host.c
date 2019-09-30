// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "create_errors_u.h"

static void _test_invalid_param(const char* path, uint32_t flags)
{
    oe_enclave_t* enclave = NULL;

    oe_enclave_config_t invalid_config = {0, {NULL}};
    oe_enclave_setting_context_switchless_t config = {2, 0};
    oe_enclave_config_t configs[] = {{
        .config_type = OE_ENCLAVE_CONFIG_CONTEXT_SWITCHLESS,
        .u.context_switchless_config = &config,
    }};

    /* Null path. */
    oe_result_t result = oe_create_create_errors_enclave(
        NULL, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Invalid enclave type. Note that 0 is now allowed! */
    result = oe_create_create_errors_enclave(
        path, (OE_ENCLAVE_TYPE_OPTEE + 1), flags, NULL, 0, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Invalid flags. */
    result = oe_create_create_errors_enclave(
        path,
        OE_ENCLAVE_TYPE_AUTO,
        OE_ENCLAVE_FLAG_RESERVED,
        NULL,
        0,
        &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Invalid configuration with incorrect **config_count** */
    result = oe_create_create_errors_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, &invalid_config, 0, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Invalid configuration with correct **config_count** */
    result = oe_create_create_errors_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, &invalid_config, 1, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Valid configuration with incorrect **config_count** */
    result = oe_create_create_errors_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, configs, 0, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* Content size non-zero. */
    result = oe_create_create_errors_enclave(
        path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 1, &enclave);

    OE_TEST(result == OE_INVALID_PARAMETER);

    /* NULL enclave. */
    result = oe_create_create_errors_enclave(
        path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, NULL);

    OE_TEST(result == OE_INVALID_PARAMETER);
}

static void _test_enclave_path(uint32_t flags)
{
    oe_enclave_t* enclave = NULL;
    oe_result_t result;

    /* Test empty path. */
    result = oe_create_create_errors_enclave(
        "", OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    OE_TEST(result == OE_FAILURE);

    /* Test nonexistent path. */
    result = oe_create_create_errors_enclave(
        "/as2/1/fv/invalid", OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

    OE_TEST(result == OE_FAILURE);

    /*
     * TODO(akagup): Add tests for the following cases. They can't be added at
     * the moment, because the ELF64 code does no validation, so the results
     * are undefined.
     */

    /* Test non ELF file. */

    /* Test non-regular file. */

    /* Test ELF file but without ".oeinfo" section. */

    /* Test ELF file but with invalid ".oeinfo" attributes. */
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    /* Test basic invalid parameter arguments. */
    _test_invalid_param(argv[1], flags);

    /* Test Enclave path parameter. */
    _test_enclave_path(flags);

    return 0;
}
