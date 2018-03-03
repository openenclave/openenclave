// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/build.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/sgxdev.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../host/enclave.h"

#if 1
#define USE_DRIVER
#endif

static OE_SGXDevice* OpenDevice()
{
#ifdef USE_DRIVER
    return __OE_OpenSGXDriver(false);
#else
    return __OE_OpenSGXMeasurer();
#endif
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
    OE_SGXDevice* dev = NULL;
    OE_Enclave enclave;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if (!(dev = OpenDevice()))
        OE_PutErr("__OE_OpenSGXDriver() failed");

    if ((result = __OE_BuildEnclave(
             dev, argv[1], GetEnclaveSettings(), false, false, &enclave)) !=
        OE_OK)
    {
        OE_PutErr("__OE_AddSegmentPages(): result=%u", result);
    }

    printf("MRENCLAVE=%s\n", OE_SHA256StrOf(&enclave.hash).buf);

    printf("BASEADDR=%016lx\n", enclave.addr);

    for (size_t i = 0; i < enclave.num_bindings; i++)
        printf("TCS[%zu]=%016lx\n", i, enclave.bindings[i].tcs);

    return 0;
}
