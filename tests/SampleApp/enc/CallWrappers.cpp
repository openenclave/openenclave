// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

#define __oe_debug_break()

int SecureStrPatching(const char* src, char* dst, int dst_length);

struct SecureStrPatchingARGS
{
    const char* src;
    char* dst;
    int dst_length;
    int ret;
};

OE_ECALL oe_result_t SecureStrPatching(void* data)
{
    if (!oe_is_outside_enclave(data, sizeof(SecureStrPatchingARGS)))
        return OE_FAILURE;

    SecureStrPatchingARGS* args = (SecureStrPatchingARGS*)data;
    args->ret = SecureStrPatching(args->src, args->dst, args->dst_length);
    return OE_OK;
}

int HostUnsecureStrPatching(const char* src, char* dst, int dst_length)
{
    SecureStrPatchingARGS* args;

    args =
        (SecureStrPatchingARGS*)oe_host_malloc(sizeof(SecureStrPatchingARGS));
    if (args == NULL)
    {
        __oe_debug_break();
    }
    args->dst = dst;
    args->src = src;
    args->dst_length = dst_length;
    if (oe_call_host("UnsecureStrPatching", args) != OE_OK)
    {
        __oe_debug_break();
    }
    oe_host_free(args);
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
