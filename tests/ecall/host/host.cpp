// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

#if 0
#define ECHO
#endif

uint64_t prev;

void TestECall(OE_Enclave* enclave)
{
    OE_Result result;
    TestArgs args;
    memset(&args, 0, sizeof(TestArgs));

    {
        result = OE_CallEnclave(enclave, "Test", &args);
        OE_TEST(result == OE_OK);

        OE_TEST(args.self = &args);
        OE_TEST(args.magic == NEW_MAGIC);
        OE_TEST(args.magic2 == NEW_MAGIC);
    }

    OE_TEST(args.mm == 12);
    OE_TEST(args.dd == 31);
    OE_TEST(args.yyyy == 1962);

    OE_TEST(args.setjmpResult == 999);

#ifdef ECHO
    printf("setjmpResult=%u\n", args.setjmpResult);
    printf("%02u/%02u/%04u\n", args.mm, args.dd, args.yyyy);

    printf("baseHeapPage=%llu\n", OE_LLU(args.baseHeapPage));
    printf("numHeapPages=%llu\n", OE_LLU(args.numHeapPages));
    printf("numPages=%llu\n", OE_LLU(args.numPages));
    printf("base=%p\n", args.base);

    void* heap = (unsigned char*)args.base + (args.baseHeapPage * 4096);
    printf("heap=%p\n", heap);
    printf("diff=%zu\n", (unsigned char*)heap - (unsigned char*)args.base);

    printf("threadDataAddr=%llx\n", OE_LLX(args.threadDataAddr));

    printf("last_sp=%llx\n", OE_LLX(args.threadData.last_sp));
#endif

    prev = args.threadData.last_sp;
}

void TestUserDefinedECall(OE_Enclave* enclave)
{
    uint64_t argOut = 0;

    OE_ECall(enclave, 0, 1000, &argOut);
    OE_TEST(argOut == 3000);
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

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    const size_t N = 10000;

    printf("=== TestECall()\n");
    for (size_t i = 0; i < N; i++)
    {
        TestECall(enclave);
    }

    printf("=== TestUserDefinedECall()\n");
    TestUserDefinedECall(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
