// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug_mode_u.h"

#define SKIP_RETURN_CODE 2

typedef enum
{
    SGX_NON_DEBUG,
    SGX_DEBUG,
    SGX_DEBUG_AUTO
} sgx_debug_t;

static uint32_t _create_flags(sgx_debug_t debug_type)
{
    uint32_t flags = oe_get_create_flags();

    if (debug_type == SGX_DEBUG)
        flags |= (uint32_t)OE_ENCLAVE_FLAG_DEBUG;
    else if (debug_type == SGX_NON_DEBUG)
        flags &= ~(uint32_t)OE_ENCLAVE_FLAG_DEBUG;
    else if (debug_type == SGX_DEBUG_AUTO)
    {
        flags &= ~(uint32_t)OE_ENCLAVE_FLAG_DEBUG;
        flags |= (uint32_t)OE_ENCLAVE_FLAG_DEBUG_AUTO;
    }

    return flags;
}

static void _launch_enclave_success(
    const char* path,
    const uint32_t flags,
    int expected_debug_mode)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_debug_mode_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_debug_mode_enclave(): result=%u", result);

    int debug_mode;
    if ((result = test(enclave, &debug_mode)) != OE_OK)
        oe_put_err("test: result=%u", result);

    OE_TEST(debug_mode == expected_debug_mode);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

static void _launch_enclave_fail(
    const char* path,
    const uint32_t flags,
    oe_result_t expected_result)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result = oe_create_debug_mode_enclave(
        path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result == OE_OK)
        oe_terminate_enclave(enclave);

    if (result != expected_result)
        oe_put_err(
            "oe_create_debug_mode_enclave(): got result=%u, expected=%u",
            result,
            expected_result);
}

static void _test_debug_signed(const char* path)
{
    /* Signed debug mode should always pass. */
    _launch_enclave_success(path, _create_flags(SGX_DEBUG), 1);
    _launch_enclave_success(path, _create_flags(SGX_DEBUG_AUTO), 1);
    if (oe_has_sgx_quote_provider())
    {
        /* Only works with FLC */
        _launch_enclave_success(path, _create_flags(SGX_NON_DEBUG), 0);
    }
}

static void _test_debug_unsigned(const char* path)
{
    /* Debug mode should pass. Non-debug should fail. */
    _launch_enclave_success(path, _create_flags(SGX_DEBUG), 1);
    _launch_enclave_success(path, _create_flags(SGX_DEBUG_AUTO), 1);
    _launch_enclave_fail(path, _create_flags(SGX_NON_DEBUG), OE_FAILURE);
}

static void _test_non_debug_signed(const char* path)
{
    /* Debug mode should fail. Non-debug mode should pass. */
    _launch_enclave_fail(path, _create_flags(SGX_DEBUG), OE_DEBUG_DOWNGRADE);
    if (oe_has_sgx_quote_provider())
    {
        /* Only works with FLC */
        _launch_enclave_success(path, _create_flags(SGX_NON_DEBUG), 0);
        _launch_enclave_success(path, _create_flags(SGX_DEBUG_AUTO), 0);
    }
}

static void _test_non_debug_unsigned(const char* path)
{
    /* Unsigned non-debug should always fail. */
    _launch_enclave_fail(path, _create_flags(SGX_DEBUG), OE_DEBUG_DOWNGRADE);
    _launch_enclave_fail(path, _create_flags(SGX_NON_DEBUG), OE_FAILURE);
    _launch_enclave_fail(path, _create_flags(SGX_DEBUG_AUTO), OE_FAILURE);
}

int main(int argc, const char* argv[])
{
    if (argc != 4)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE [debug|nodebug] [signed|unsigned]\n",
            argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf("=== Skipped unsupported test in simulation mode "
               "(debug)\n");
        return SKIP_RETURN_CODE;
    }

    const bool debug = strcmp(argv[2], "debug") == 0;
    const bool is_signed = strcmp(argv[3], "signed") == 0;

    if (debug && is_signed)
        _test_debug_signed(argv[1]);
    else if (debug)
        _test_debug_unsigned(argv[1]);
    else if (is_signed)
        _test_non_debug_signed(argv[1]);
    else
        _test_non_debug_unsigned(argv[1]);

    return 0;
}
