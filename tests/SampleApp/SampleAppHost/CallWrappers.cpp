// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>

struct SecureStrPatchingARGS
{
    const char* src;
    char* dst;
    int dstLength;
    int ret;
};

int EnclaveSecureStrPatching(
    oe_enclave_t* Enclave,
    const char* src,
    char* dst,
    int dstLength)
{
    SecureStrPatchingARGS* data =
        (SecureStrPatchingARGS*)malloc(sizeof(SecureStrPatchingARGS));
    data->dst = dst;
    data->src = src;
    data->dstLength = dstLength;
    if (oe_call_enclave(Enclave, "SecureStrPatching", data) != OE_OK)
    {
        fprintf(stderr, "Error failed callin with error\n");
        exit(1);
    }
    return data->ret;
}

int UnsecureStrPatching(const char* src, char* dst, int dstLength);

OE_OCALL void UnsecureStrPatching(void* data)
{
    SecureStrPatchingARGS* args = (SecureStrPatchingARGS*)data;
    args->ret = UnsecureStrPatching(args->src, args->dst, args->dstLength);
}
