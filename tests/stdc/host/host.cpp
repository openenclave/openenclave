#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <openenclave/host.h>
#include "../args.h"

#if 0
# define ECHO
#endif

uint64_t prev;

void TestStdc(OE_Enclave* enclave)
{
    OE_Result result;
    TestArgs args;

    printf("=== %s() \n", __FUNCTION__);
    result = OE_CallEnclave(enclave, "Test", &args);
    assert(result == OE_OK);
    assert(strcmp(args.buf1, "AAABBBCCC") == 0);
    assert(strcmp(args.buf2, "value=100") == 0);
    assert(args.strdupOk);
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

    if ((result = OE_CreateEnclave(argv[1], CREATE_FLAGS, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestStdc(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
