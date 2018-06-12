// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

static bool _func1Called = false;

OE_OCALL void Func1(void* args)
{
    _func1Called = true;
}

void MyOCall(uint64_t argIn, uint64_t* argOut)
{
    if (argOut)
        *argOut = argIn * 7;
}

static bool _func2Ok;

OE_OCALL void Func2(void* args)
{
    // unsigned char* buf = (unsigned char*)args;
    _func2Ok = true;
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
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    /* Call Test2() */
    {
        Test2Args args;
        args.in = 123456789;
        args.out = 0;
        OE_Result result = OE_CallEnclave(enclave, "Test2", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.out == args.in);
    }

    /* Call Test4() */
    {
        OE_Result result = OE_CallEnclave(enclave, "Test4", NULL);
        OE_TEST(result == OE_OK);
        OE_TEST(_func2Ok);
    }

    /* Call SetTSD() */
    {
        SetTSDArgs args;
        args.value = (void*)0xAAAAAAAABBBBBBBB;
        OE_Result result = OE_CallEnclave(enclave, "SetTSD", &args);
        OE_TEST(result == OE_OK);
    }

    /* Call GetTSD() */
    {
        GetTSDArgs args;
        args.value = 0;
        OE_Result result = OE_CallEnclave(enclave, "GetTSD", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.value == (void*)0xAAAAAAAABBBBBBBB);
    }

    /* Call TestMyOCall() */
    {
        OE_Result result = OE_RegisterOCall(0, MyOCall);
        OE_TEST(result == OE_OK);

        TestMyOCallArgs args;
        args.result = 0;
        result = OE_CallEnclave(enclave, "TestMyOCall", &args);
        OE_TEST(result == OE_OK);
        OE_TEST(args.result == 7000);
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
