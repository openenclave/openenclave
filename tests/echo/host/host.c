#include <openenclave/host.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../args.h"

OE_OCALL void Echo(void* args_)
{
    EchoArgs* args = (EchoArgs*)args_;

    if (!(args->out = strdup(args->in)))
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

#if 0
    const uint64_t flags = OE_FLAG_DEBUG | OE_FLAG_SIMULATE;
#else
    const uint64_t flags = OE_FLAG_DEBUG;
#endif

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    EchoArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    if (!(args.in = strdup("Hello World")))
        OE_PutErr("strdup() failed");

    if ((result = OE_CallEnclave(enclave, "Echo", &args)) != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL failed args.result=%d", args.ret);

    assert(args.in);
    assert(args.out);

    if (strcmp(args.in, args.out) != 0)
        OE_PutErr("ecall failed: %s != %s\n", args.in, args.out);

    free((char*)args.in);
    free((char*)args.out);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
