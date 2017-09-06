#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include "../args.h"

#if 0
# define ECHO
#endif

uint64_t prev;

void TestStdcxx(OE_Enclave* enclave)
{
    OE_Result result;
    TestArgs args;

    printf("=== %s() \n", __FUNCTION__);
    result = OE_CallEnclave(enclave, "Test", &args);
    assert(result == OE_OK);
    assert(args.ret == 0);
    assert(args.caught);
    assert(args.dynamicCastWorks);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const oe_uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestStdcxx(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
