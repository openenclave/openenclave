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

void TestECALL(OE_Enclave* enclave)
{
    OE_Result result;
    TestArgs args;
    memset(&args, 0, sizeof(TestArgs));

    {
        result = OE_CallEnclave(enclave, "Test", &args);
        assert(result == OE_OK);

        assert(args.self = &args);
        assert(args.magic == NEW_MAGIC);
        assert(args.magic2 == NEW_MAGIC);
    }

    assert(args.mm == 12);
    assert(args.dd == 31);
    assert(args.yyyy == 1962);

    assert(args.setjmpResult == 999);

#ifdef ECHO
    printf("setjmpResult=%u\n", args.setjmpResult);
    printf("%02u/%02u/%04u\n", args.mm, args.dd, args.yyyy);

    printf("baseHeapPage=%llu\n", args.baseHeapPage);
    printf("numHeapPages=%llu\n", args.numHeapPages);
    printf("numPages=%llu\n", args.numPages);
    printf("base=%p\n", args.base);

    void* heap = (unsigned char*)args.base + (args.baseHeapPage * 4096);
    printf("heap=%p\n", heap);
    printf("diff=%zu\n", (unsigned char*)heap - (unsigned char*)args.base);

    printf("threadDataAddr=%llx\n", args.threadDataAddr);

    printf("last_sp=%llx\n", args.threadData.last_sp);
#endif

    prev = args.threadData.last_sp;
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

    const size_t N = 10000;

    printf("=== TestECALL()\n");
    for (size_t i = 0; i < N; i++)
    {
        TestECALL(enclave);
    }

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
