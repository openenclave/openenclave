#ifndef _new_args_h
#define _new_args_h

#include <oeinternal/sgxtypes.h>

#define NEW_MAGIC 0x7541cc89

#define FUNC1 1

typedef struct _TestArgs
{
    void* self;
    unsigned int magic;
    unsigned long long baseHeapPage;
    unsigned long long numHeapPages;
    unsigned long long numPages;
    const void* base;
    OE_ThreadData threadData;
    unsigned long long threadDataAddr;
    unsigned int mm;
    unsigned int dd;
    unsigned int yyyy;
    unsigned int setjmpResult;
    unsigned int magic2;
}
TestArgs;

#endif /* _new_args_h */
