#include <cstring>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <assert.h>
#include <openenclave.h>
#include "../args.h"

static bool _func1Called = false;

OE_OCALL void Func1(void* args)
{
    _func1Called = true;
}

static bool _func2Ok;

OE_OCALL void Func2(void* args)
{
    //unsigned char* buf = (unsigned char*)args;
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

#if 1
    const uint64_t flags = OE_FLAG_DEBUG | OE_FLAG_SIMULATE;
#else
    const uint64_t flags = OE_FLAG_DEBUG;
#endif

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("__OE_AddSegmentPages(): result=%u", result);

    /* Call Test2() */
    {
        Test2Args args;
        args.in = 123456789;
        args.out = 0;
        OE_Result result = OE_CallEnclave(enclave, "Test2", &args);
        assert(result == OE_OK);
        assert(args.out == args.in);
    }

    /* Call TestAllocator() */
    {
        TestAllocatorArgs args;
        args.ret = -1;
        OE_Result result = OE_CallEnclave(enclave, "TestAllocator", &args);
        assert(result == OE_OK);
        assert(args.ret == 0);
    }

    /* Call Test3() */
    {
        OE_Result result = OE_CallEnclave(enclave, "Test3", NULL);
        assert(result == OE_OK);
        assert(_func1Called);
    }

    /* Call Test4() */
    {
        OE_Result result = OE_CallEnclave(enclave, "Test4", NULL);
        assert(result == OE_OK);
        assert(_func2Ok);
    }

    /* Call SetTSD() */
    {
        SetTSDArgs args;
        args.value = (void*)0xAAAAAAAABBBBBBBB;
        OE_Result result = OE_CallEnclave(enclave, "SetTSD", &args);
        assert(result == OE_OK);
    }

    /* Call GetTSD() */
    {
        GetTSDArgs args;
        args.value = 0;
        OE_Result result = OE_CallEnclave(enclave, "GetTSD", &args);
        assert(result == OE_OK);
        assert(args.value == (void*)0xAAAAAAAABBBBBBBB);
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
