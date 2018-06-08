// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/sgxcreate.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../host/enclave.h"

static oe_result_t InitializeContext(oe_sgx__load_context_t* context)
{
#ifdef MEASURE_ONLY
    const oe_sgx__load_type_t type = OE_SGX_LOAD_TYPE_MEASURE;
#else
    const oe_sgx__load_type_t type = OE_SGX_LOAD_TYPE_CREATE;
#endif
    return oe_sgx__initialize_load_context(context, type, OE_ENCLAVE_FLAG_DEBUG);
}

static const oe_sgx__enclave_properties_t* GetEnclaveProperties()
{
#ifdef USE_DRIVER
    return NULL;
#else
    static oe_sgx__enclave_properties_t properties;

    memset(&properties, 0, sizeof(oe_sgx__enclave_properties_t));
    properties.config.attributes = OE_SGX_FLAGS_DEBUG;
    properties.header.sizeSettings.numHeapPages = 2;
    properties.header.sizeSettings.numStackPages = 1;
    properties.header.sizeSettings.numTCS = 2;

    return &properties;
#endif
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_sgx__load_context_t context;
    oe_enclave_t enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if (InitializeContext(&context) != OE_OK)
        oe_puterr("InitializeContext() failed");

    if ((result = oe_sgx__build_enclave(
             &context, argv[1], GetEnclaveProperties(), &enclave)) != OE_OK)
    {
        oe_puterr("oe_sgx__build_enclave(): result=%u", result);
    }

    char buf[2 * OE_SHA256_SIZE + 1];
    oe_hex_string(buf, sizeof(buf), &enclave.hash, sizeof(enclave.hash));
    printf("MRENCLAVE=%s\n", buf);

    printf("BASEADDR=%016llx\n", OE_LLX(enclave.addr));

    for (size_t i = 0; i < enclave.num_bindings; i++)
        printf("TCS[%zu]=%016llx\n", i, OE_LLX(enclave.bindings[i].tcs));

    return 0;
}
