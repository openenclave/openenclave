#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/error.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../args.h"

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf("=== This program is used to test basic vector exception functionalities.");

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    Args args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;

    if ((result = OE_CallEnclave(enclave, "TestVectorException", &args)) != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL TestVectorException failed args.result=%d", args.ret);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (VectorException)\n");

    return 0;
}
