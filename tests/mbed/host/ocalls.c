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
    FILE* F_ptr;
    char* path;
    char* mode;
    char* buf;
    void* ptr;
    int ret;

    long int li_var;
    int i_var;
    int len;

} F_Args;

OE_OCALL void OE_FOpen(void* FileArgs)
{
    FILE* fp;
    F_Args* args = (F_Args*)FileArgs;

    OE_TRACE_INFO("#### %s ###########\n", args->path);

    fp = fopen(args->path, args->mode);
    if (fp == NULL)
        printf("fopen error");
    else
    {
        OE_TRACE_INFO("\n file opened address fp =%p &&&&&&&&&\n", fp);
        args->F_ptr = fp;
    }
    return;
}

OE_OCALL void OE_FClose(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fclose(args->F_ptr);

    OE_TRACE_INFO("\n fclose Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FEof(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = feof(args->F_ptr);

    OE_TRACE_INFO("\n feof Ret = %d \n", ret);
    args->ret = ret;
    return;
}

OE_OCALL void OE_FGets(void* FileArgs)
{
    char* ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fgets(args->buf, args->len, args->F_ptr);

    OE_TRACE_INFO("\n fgets Ret = %d --- buf: %s \n", ret, args->buf);
    args->ptr = (void*)ret;
    return;
}

OE_OCALL void OE_FPutc(void* FileArgs)
{
    int ret;
    F_Args* args = (F_Args*)FileArgs;

    ret = fputc(args->i_var, args->F_ptr);

    OE_TRACE_INFO("\n fputc Ret = %d \n", ret);
    args->ret = ret;
    return;
}

