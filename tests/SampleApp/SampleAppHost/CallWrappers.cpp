#include <openenclave/host.h>

struct SecureStrPatchingARGS
{
    const char* src;
    char* dst;
    int dstLength;
    int ret;
};

int EnclaveSecureStrPatching(OE_Enclave* Enclave, const char* src, char* dst, int dstLength)
{
    SecureStrPatchingARGS* data = (SecureStrPatchingARGS*)malloc(sizeof(SecureStrPatchingARGS));
    data->dst = dst;
    data->src = src;
    data->dstLength = dstLength;
    if (OE_CallEnclave(Enclave, "SecureStrPatching", data) != OE_OK)
    {
        fprintf(stderr, "Error failed callin with error\n");
        exit(1);
    }
    return data->ret;
}

int UnsecureStrPatching(const char* src, char* dst, int dstLength);

OE_OCALL OE_Result UnsecureStrPatching(void* data)
{
    SecureStrPatchingARGS* args = (SecureStrPatchingARGS*)data;
    args->ret = UnsecureStrPatching(args->src, args->dst, args->dstLength);
    return OE_OK;
}
