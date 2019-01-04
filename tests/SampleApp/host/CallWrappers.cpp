// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>

struct SecureStrPatchingARGS
{
    const char* src;
    char* dst;
    int dst_length;
    int ret;
};

int EnclaveSecureStrPatching(
    oe_enclave_t* Enclave,
    const char* src,
    char* dst,
    int dst_length)
{
    SecureStrPatchingARGS* data =
        (SecureStrPatchingARGS*)malloc(sizeof(SecureStrPatchingARGS));
    data->dst = dst;
    data->src = src;
    data->dst_length = dst_length;
    if (oe_call_enclave(Enclave, "SecureStrPatching", data) != OE_OK)
    {
        fprintf(stderr, "Error failed callin with error\n");
        exit(1);
    }
    return data->ret;
}

int UnsecureStrPatching(const char* src, char* dst, int dst_length);

OE_OCALL void UnsecureStrPatching(void* data)
{
    SecureStrPatchingARGS* args = (SecureStrPatchingARGS*)data;
    args->ret = UnsecureStrPatching(args->src, args->dst, args->dst_length);
}
