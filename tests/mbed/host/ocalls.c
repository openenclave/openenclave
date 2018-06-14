// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct _FileArgs
{
    FILE* filePtr;
    char* path;
    char* mode;
    char* buf;
    void* ptr;
    int ret;

    long int li_var;
    int i_var;
    int len;

} FileArgs;

OE_OCALL void mbed_test_fopen(void* fileArgs)
{
    FILE* fp;
    FileArgs* args = (FileArgs*)fileArgs;

    OE_TRACE_INFO("#### %s ###########\n", args->path);

    fp = fopen(args->path, args->mode);
    if (fp == NULL)
        printf("fopen error");
    else
    {
        OE_TRACE_INFO("\n file opened address fp =%p &&&&&&&&&\n", fp);
        args->filePtr = fp;
    }
    return;
}

OE_OCALL void mbed_test_fclose(void* fileArgs)
{
    int ret;
    FileArgs* args = (FileArgs*)fileArgs;

    ret = fclose(args->filePtr);

    OE_TRACE_INFO("\n fclose Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void mbed_test_feof(void* fileArgs)
{
    int ret;
    FileArgs* args = (FileArgs*)fileArgs;

    ret = feof(args->filePtr);

    OE_TRACE_INFO("\n feof Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void mbed_test_fgets(void* fileArgs)
{
    char* ret;
    FileArgs* args = (FileArgs*)fileArgs;

    ret = fgets(args->buf, args->len, args->filePtr);

    OE_TRACE_INFO("\n fgets Ret = %d --- buf: %s \n", ret, args->buf);
    args->ptr = (void*)ret;
    return;
}

OE_OCALL void mbed_test_fputc(void* fileArgs)
{
    int ret;
    FileArgs* args = (FileArgs*)fileArgs;

    ret = fputc(args->i_var, args->filePtr);

    OE_TRACE_INFO("\n fputc Ret = %d \n", ret);
    args->ret = ret;
    return;
}
