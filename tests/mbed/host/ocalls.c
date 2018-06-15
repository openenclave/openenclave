// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1

#include <openenclave/host.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct _file_args
{
    FILE* file_ptr;
    char* path;
    char* mode;
    char* buf;
    void* ptr;
    int ret;

    long int li_var;
    int i_var;
    int len;

} FileArgs;

OE_OCALL void mbed_test_fopen(void* file_args)
{
    FILE* fp;
    FileArgs* args = (FileArgs*)file_args;

    OE_TRACE_INFO("#### %s ###########\n", args->path);

    fp = fopen(args->path, args->mode);
    if (fp == NULL)
        printf("fopen error");
    else
    {
        OE_TRACE_INFO("\n file opened address fp =%p &&&&&&&&&\n", fp);
        args->file_ptr = fp;
    }
    return;
}

OE_OCALL void mbed_test_fclose(void* file_args)
{
    int ret;
    FileArgs* args = (FileArgs*)file_args;

    ret = fclose(args->file_ptr);

    OE_TRACE_INFO("\n fclose Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void mbed_test_feof(void* file_args)
{
    int ret;
    FileArgs* args = (FileArgs*)file_args;

    ret = feof(args->file_ptr);

    OE_TRACE_INFO("\n feof Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void mbed_test_fgets(void* file_args)
{
    char* ret;
    FileArgs* args = (FileArgs*)file_args;

    ret = fgets(args->buf, args->len, args->file_ptr);

    OE_TRACE_INFO("\n fgets Ret = %d --- buf: %s \n", ret, args->buf);
    args->ptr = (void*)ret;
    return;
}

OE_OCALL void mbed_test_fputc(void* file_args)
{
    int ret;
    FileArgs* args = (FileArgs*)file_args;

    ret = fputc(args->i_var, args->file_ptr);

    OE_TRACE_INFO("\n fputc Ret = %d \n", ret);
    args->ret = ret;
    return;
}
