// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/build.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/sgxdev.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../host/enclave.h"

static OE_Result InitializeContext(OE_SgxLoadContext* context)
{
#ifdef MEASURE_ONLY
    const OE_SgxLoadType type = OE_SGXLOAD_MEASURE;
#else
    const OE_SgxLoadType type = OE_SGXLOAD_CREATE;
#endif
    return _InitializeLoadContext(context, type, OE_FLAG_DEBUG);
}

static const OE_EnclaveSettings* GetEnclaveSettings()
{
#ifdef USE_DRIVER
    return NULL;
#else
    static OE_EnclaveSettings settings;

    memset(&settings, 0, sizeof(OE_EnclaveSettings));
    settings.debug = 1;
    settings.numHeapPages = 2;
    settings.numStackPages = 1;
    settings.numTCS = 2;

    return &settings;
#endif
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_SgxLoadContext context;
    OE_Enclave enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if (InitializeContext(&context) != OE_OK)
        OE_PutErr("InitializeContext() failed");

    if ((result = __OE_BuildEnclave(
             &context, argv[1], GetEnclaveSettings(), &enclave)) != OE_OK)
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
