#ifndef _ocall_args_h
#define _ocall_args_h

#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/calls.h>

#define TEST1_MAGIC 0xec9a613e

typedef struct _Test1Args
{
    void* self;


    /* --- Input arguments --- */

    long inNum;

    const char* inStr;

    /* --- Output arguments --- */

    long op;
    unsigned int magic;

    char* str;

    volatile void* sp1;
    volatile void* sp2;
    volatile void* sp3;

    unsigned int* mem;

    void* func;

    int ret;
}
Test1Args;

typedef struct _Test2Args
{
    long in;
    long out;
}
Test2Args;

typedef struct _TestAllocatorArgs
{
    int ret;
}
TestAllocatorArgs;

typedef struct _Func1Args
{
    char buf[128];
}
Func1Args;

typedef struct _SetTSDArgs
{
    void* value;
    int ret;
}
SetTSDArgs;

typedef struct _GetTSDArgs
{
    void* value;
    int ret;
}
GetTSDArgs;

#endif /* _ocall_args_h */
