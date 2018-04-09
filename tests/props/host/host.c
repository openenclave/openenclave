// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include "../../../host/enclave.h"
#include "../args.h"

static void _CheckProperties(
    OE_EnclaveProperties_SGX* props,
    bool isSigned,
    uint16_t productID,
    uint16_t securityVersion,
    uint64_t attributes,
    uint64_t numHeapPages,
    uint64_t numStackPages,
    uint64_t numTCS)
{
    const OE_EnclavePropertiesHeader* header = &props->header;
    const OE_EnclaveConfig_SGX* config = &props->config;

    /* Check the header */
    OE_TEST(header->size == sizeof(OE_EnclaveProperties_SGX));
    OE_TEST(header->enclaveType == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(header->sizeSettings.numHeapPages == numHeapPages);
    OE_TEST(header->sizeSettings.numStackPages == numStackPages);
    OE_TEST(header->sizeSettings.numTCS == numTCS);

    /* Check the SGX config */
    OE_TEST(config->productID == productID);
    OE_TEST(config->securityVersion == securityVersion);
    OE_TEST(config->padding == 0);
    OE_TEST(config->attributes == attributes);

    /* Initailize a zero-filled sigstruct */
    const uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE] = {0};

    /* Check for presence or absence of the signature */
    if (isSigned)
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) != 0);
    else
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) == 0);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;
    bool isSigned = false;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Extract "signed" or "unsigned" command-line argument */
    if (strcmp(argv[2], "signed") == 0)
    {
        isSigned = true;
    }
    else if (strcmp(argv[2], "unsigned") == 0)
    {
        isSigned = false;
    }
    else
    {
        fprintf(stderr, "%s: invalid argument: %s\n", argv[0], argv[2]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    /* Check expected enclave property values */
    if (isSigned)
    {
        _CheckProperties(
            &enclave->properties,
            isSigned,
            0,                                           /* productID */
            0,                                           /* securityVersion */
            OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT, /* attributes */
            2048,                                        /* numHeapPages  */
            1024,                                        /* numStackPages */
            8);                                          /* numTCS */
    }
    else
    {
        _CheckProperties(
            &enclave->properties,
            isSigned,
            1234,                                        /* productID */
            5678,                                        /* securityVersion */
            OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT, /* attributes */
            1024,                                        /* numHeapPages  */
            512,                                         /* numStackPages */
            4);                                          /* numTCS */
    }

    Args args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;

    if ((result = OE_CallEnclave(enclave, "Test", &args)) != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL failed args.result=%d", args.ret);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
