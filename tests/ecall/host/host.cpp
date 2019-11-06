// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "ecall_u.h"

#if 0
#define ECHO
#endif

uint64_t prev;

void TestECall(oe_enclave_t* enclave)
{
    oe_result_t result;
    test_args args;
    memset(&args, 0, sizeof(test_args));

    {
        result = enc_test(enclave, &args);
        OE_TEST(result == OE_OK);

        OE_TEST(args.self = &args);
        OE_TEST(args.magic == NEW_MAGIC);
        OE_TEST(args.magic2 == NEW_MAGIC);
    }

    OE_TEST(args.mm == 12);
    OE_TEST(args.dd == 31);
    OE_TEST(args.yyyy == 1962);

    OE_TEST(args.setjmp_result == 999);

#ifdef ECHO
    printf("setjmpResult=%u\n", args.setjmp_result);
    printf("%02u/%02u/%04u\n", args.mm, args.dd, args.yyyy);

    printf("baseHeapPage=%llu\n", OE_LLU(args.base_heap_page));
    printf("num_heap_pages=%llu\n", OE_LLU(args.num_heap_pages));
    printf("numPages=%llu\n", OE_LLU(args.num_pages));
    printf("base=%p\n", args.base);

    void* heap = (unsigned char*)args.base + (args.base_heap_page * 4096);
    printf("heap=%p\n", heap);
    printf("diff=%zu\n", (unsigned char*)heap - (unsigned char*)args.base);

    printf("threadDataAddr=%llx\n", OE_LLX(args.thread_data_addr));

    printf("last_sp=%llx\n", OE_LLX(args.thread_data.last_sp));
#endif

    prev = args.thread_data.last_sp;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_ecall_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        oe_put_err("oe_create_ecall_enclave(): result=%u", result);
    }

    const size_t N = 10000;

    printf("=== TestECall()\n");
    for (size_t i = 0; i < N; i++)
    {
        TestECall(enclave);
    }

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
