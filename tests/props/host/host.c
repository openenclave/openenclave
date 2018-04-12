// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/raise.h>
#include <openenclave/host.h>
#include <stdio.h>
#include "../../../host/enclave.h"
#include "../args.h"

static void _CheckProperties(
    OE_SGXEnclaveProperties* props,
    bool isSigned,
    uint16_t productID,
    uint16_t securityVersion,
    uint64_t attributes,
    uint64_t numHeapPages,
    uint64_t numStackPages,
    uint64_t numTCS)
{
    const OE_EnclavePropertiesHeader* header = &props->header;
    const OE_SGXEnclaveConfig* config = &props->config;

    /* Check the header */
    OE_TEST(header->size == sizeof(OE_SGXEnclaveProperties));
    OE_TEST(header->enclaveType == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(header->sizeSettings.numHeapPages == numHeapPages);
    OE_TEST(header->sizeSettings.numStackPages == numStackPages);
    OE_TEST(header->sizeSettings.numTCS == numTCS);

    /* Check the SGX config */
    OE_TEST(config->productID == productID);
    OE_TEST(config->securityVersion == securityVersion);
    OE_TEST(config->padding == 0);
    OE_TEST(config->attributes == attributes);

    /* Initialize a zero-filled sigstruct */
    const uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE] = {0};

    /* Check for presence or absence of the signature */
    if (isSigned)
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) != 0);
    else
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) == 0);
}

static OE_Result _SGXLoadEnclaveProperties(
    const char* path,
    OE_SGXEnclaveProperties* properties)
{
    OE_Result result = OE_UNEXPECTED;
    Elf64 elf = ELF64_INIT;

    if (properties)
        memset(properties, 0, sizeof(OE_SGXEnclaveProperties));

    /* Check parameters */
    if (!path || !properties)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF image */
    if (Elf64_Load(path, &elf) != 0)
        OE_RAISE(OE_FAILURE);

    /* Load the SGX enclave properties */
    if (OE_SGXLoadProperties(&elf, OE_INFO_SECTION_NAME, properties) !=
        OE_OK)
    {
        OE_RAISE(OE_NOT_FOUND);
    }

    result = OE_OK;

done:

    if (elf.magic == ELF_MAGIC)
        Elf64_Unload(&elf);

    return result;
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;
    bool isSigned = false;
    OE_SGXEnclaveProperties properties;

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

    /* Load the enclave properties */
    if ((result = _SGXLoadEnclaveProperties(argv[1], &properties)) != OE_OK)
    {
        OE_PutErr("OE_SGXLoadProperties(): result=%u", result);
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    /* Check expected enclave property values */
    if (isSigned)
    {
        _CheckProperties(
            &properties,
            isSigned,
            1111,                                        /* productID */
            2222,                                        /* securityVersion */
            OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT, /* attributes */
            2048,                                        /* numHeapPages  */
            1024,                                        /* numStackPages */
            8);                                          /* numTCS */
    }
    else
    {
        _CheckProperties(
            &properties,
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
