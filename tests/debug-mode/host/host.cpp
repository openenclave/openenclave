// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE [debug|nodebug]\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    const bool debug = strcmp(argv[2], "debug") == 0;

    uint32_t new_flags = flags;
    if (debug)
        new_flags |= (uint32_t) OE_ENCLAVE_FLAG_DEBUG;
    else
        new_flags &= (uint32_t) ~OE_ENCLAVE_FLAG_DEBUG;

    /* Host and enclave match for debug mode. */
    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             new_flags,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    bool args = debug;
    if ((result = oe_call_enclave(enclave, "Test", &args)) != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    /* Enclave and host mismatch. */
    new_flags = flags;
    if (debug)
        new_flags &= (uint32_t) ~OE_ENCLAVE_FLAG_DEBUG;
    else
        new_flags |= (uint32_t) OE_ENCLAVE_FLAG_DEBUG;

    result = oe_create_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, new_flags, NULL, 0, &enclave);

    /*
     * For the non debug case, `oe_create_enclave` should error if debug mode
     * was requested.
     */
    if (!debug)
    {
        if (result == OE_OK)
        {
            oe_terminate_enclave(enclave);
            oe_put_err("oe_call_enclave(): debug allowed when not supported");
        }
        return 0;
    }

    /* For the debug case, we should allow non-debug enclave creation. */
    if (result != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    args = debug;
    if ((result = oe_call_enclave(enclave, "Test", &args)) != OE_OK)
        oe_put_err("oe_call_enclave(): result=%u", result);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    return 0;
}
