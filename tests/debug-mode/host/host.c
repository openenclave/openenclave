// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SKIP_RETURN_CODE 2

static uint32_t _CreateFlags(bool debug)
{
    uint32_t flags = oe_get_create_flags();

    if (debug)
        flags |= (uint32_t)OE_ENCLAVE_FLAG_DEBUG;
    else
        flags &= ~(uint32_t)OE_ENCLAVE_FLAG_DEBUG;

    return flags;
}

static void _LaunchEnclaveSuccess(const char* path, const uint32_t flags)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result =
        oe_create_enclave(path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    int ret;
    if ((result = oe_call_enclave(enclave, "Test", &ret)) != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);
}

static void _LaunchEnclaveFail(
    const char* path,
    const uint32_t flags,
    oe_result_t expectedResult)
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    result =
        oe_create_enclave(path, OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result == OE_OK)
        oe_terminate_enclave(enclave);

    if (result != expectedResult)
        oe_put_err(
            "oe_create_enclave(): got result=%u, expected=%u",
            result,
            expectedResult);
}

static void _TestDebugSigned(const char* path)
{
    /* Signed debug mode should always pass. */
    _LaunchEnclaveSuccess(path, _CreateFlags(true));
#if !defined(OE_USE_AESM)
    /* Only works with the NGSA SDK. */
    _LaunchEnclaveSuccess(path, _CreateFlags(false));
#endif
}

static void _TestDebugUnsigned(const char* path)
{
    /* Debug mode should pass. Non-debug should fail. */
    _LaunchEnclaveSuccess(path, _CreateFlags(true));
    _LaunchEnclaveFail(path, _CreateFlags(false), OE_FAILURE);
}

static void _TestNonDebugSigned(const char* path)
{
    /* Debug mode should fail. Non-debug mode should pass. */
    _LaunchEnclaveFail(path, _CreateFlags(true), OE_DEBUG_DOWNGRADE);
#if !defined(OE_USE_AESM)
    /* Only works with the NGSA SDK. */
    _LaunchEnclaveSuccess(path, _CreateFlags(false));
#endif
}

static void _TestNonDebugUnsigned(const char* path)
{
    /* Unsigned non-debug should always fail. */
    _LaunchEnclaveFail(path, _CreateFlags(true), OE_DEBUG_DOWNGRADE);
    _LaunchEnclaveFail(path, _CreateFlags(false), OE_FAILURE);
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
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(debug)\n");
        return SKIP_RETURN_CODE;
    }

    const bool debug = strcmp(argv[2], "debug") == 0;
    const bool isSigned = strcmp(argv[3], "signed") == 0;

    if (debug && isSigned)
        _TestDebugSigned(argv[1]);
    else if (debug)
        _TestDebugUnsigned(argv[1]);
    else if (isSigned)
        _TestNonDebugSigned(argv[1]);
    else
        _TestNonDebugUnsigned(argv[1]);

    return 0;
}
