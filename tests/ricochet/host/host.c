#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/error.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "../args.h"

static OE_Enclave* enclave = NULL;

OE_OCALL void Ricochet(void* args_)
{
    RicochetArgs* args = (RicochetArgs*)args_;

    printf("Host Ricochet(): i=%d\n", args->i);

    if (args->i < args->count)
    {
        args->i++;
        OE_Result result = OE_CallEnclave(enclave, "Ricochet", args);
        assert(result == OE_OK);
    }
}

int main(int argc, const char* argv[])
{
    OE_Result result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    for (size_t i = 0; i < 3; i++)
    {
        RicochetArgs args;
        args.i = 0;
        args.count = 16;

        if ((result = OE_CallEnclave(enclave, "Ricochet", &args)) != OE_OK)
            OE_PutErr("OE_CallEnclave() failed: result=%u", result);
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
