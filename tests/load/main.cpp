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

static const OE_EnclaveProperties_SGX* GetEnclaveProperties()
{
#ifdef USE_DRIVER
    return NULL;
#else
    static OE_EnclaveProperties_SGX properties;

    memset(&properties, 0, sizeof(OE_EnclaveProperties_SGX));
    properties.settings.attributes = OE_SGX_FLAGS_DEBUG;
    properties.header.sizeSettings.numHeapPages = 2;
    properties.header.sizeSettings.numStackPages = 1;
    properties.header.sizeSettings.numTCS = 2;

    return &properties;
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
             dev, argv[1], GetEnclaveProperties(), false, false, &enclave)) !=
        OE_OK)
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
