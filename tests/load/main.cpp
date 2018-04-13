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

static OE_Result InitializeContext(OE_SGXLoadContext* context)
{
#ifdef MEASURE_ONLY
    const OE_SGXLoadType type = OE_SGX_LOADTYPE_MEASURE;
#else
    const OE_SGXLoadType type = OE_SGX_LOADTYPE_CREATE;
#endif
    return OE_SGXInitializeLoadContext(context, type, OE_ENCLAVE_FLAG_DEBUG);
}

static const OE_SGXEnclaveProperties* GetEnclaveProperties()
{
#ifdef USE_DRIVER
    return NULL;
#else
    static OE_SGXEnclaveProperties properties;

    memset(&properties, 0, sizeof(OE_SGXEnclaveProperties));
    properties.config.attributes = OE_SGX_FLAGS_DEBUG;
    properties.header.sizeSettings.numHeapPages = 2;
    properties.header.sizeSettings.numStackPages = 1;
    properties.header.sizeSettings.numTCS = 2;

    return &properties;
#endif
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_SGXLoadContext context;
    OE_Enclave enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if (InitializeContext(&context) != OE_OK)
        OE_PutErr("InitializeContext() failed");

    if ((result = OE_SGXBuildEnclave(
             &context, argv[1], GetEnclaveProperties(), &enclave)) != OE_OK)
    {
        OE_PutErr("__OE_AddSegmentPages(): result=%u", result);
    }

    char buf[2 * OE_SHA256_SIZE + 1];
    OE_HexString(buf, sizeof(buf), &enclave.hash, sizeof(enclave.hash));
    printf("MRENCLAVE=%s\n", buf);

    printf("BASEADDR=%016lx\n", enclave.addr);

    for (size_t i = 0; i < enclave.num_bindings; i++)
        printf("TCS[%zu]=%016lx\n", i, enclave.bindings[i].tcs);

    return 0;
}
