#include <openenclave.h>

#define __OE_DebugBreak()

int SecureStrPatching(
    const char *src,
    char *dst,
    int dstLength);

struct SecureStrPatchingARGS
{
    const char *src;
    char *dst;
    int dstLength;
    int ret;
};

OE_ECALL OE_Result SecureStrPatching(void *data)
{
    if (!OE_IsOutsideEnclave(data, sizeof(SecureStrPatchingARGS)))
        return OE_FAILURE;

    SecureStrPatchingARGS* args = (SecureStrPatchingARGS*)data;
    args->ret = SecureStrPatching(args->src, args->dst, args->dstLength);
    return OE_OK;
}

int HostUnsecureStrPatching(
    const char *src,
    char *dst,
    int dstLength)
{
    SecureStrPatchingARGS* args;
    
    args = (SecureStrPatchingARGS*)OE_HostMalloc(sizeof(SecureStrPatchingARGS));
    if (args == OE_NULL)
    {
        __OE_DebugBreak();
    }
    args->dst = dst;
    args->src = src;
    args->dstLength = dstLength;
    if (OE_CallHost("UnsecureStrPatching", args) != OE_OK)
    {
        __OE_DebugBreak();
    }
    OE_HostFree(args);
    return 0;
}
