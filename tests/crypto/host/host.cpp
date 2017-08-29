#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <openenclave.h>
#include "../args.h"

#if 0
# define ECHO
#endif

uint64_t prev;

void TestStdc(OE_Enclave* enclave)
{
    OE_Result result;
    TestArgs args;

    memset(&args, 0, sizeof(args));
    result = OE_CallEnclave(enclave, "Test", &args);
    assert(result == OE_OK);

    // 71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73
    
    OE_SHA256Str str;
    OE_SHA256ToStr(&args.hash, &str);

    const char expect[] = 
        "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73";

    assert(strcmp(str.buf, expect) == 0);
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

    if ((result = OE_CreateEnclave(argv[1], 0, &enclave)) != OE_OK)
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
