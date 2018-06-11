// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <stdio.h>
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
} Args;

char* OE_HostStackStrdup(const char* str)
{
    size_t n = OE_Strlen(str);

    char* dup = (char*)OE_HostMalloc(n + 1);

    if (dup)
        OE_Memcpy(dup, str, n + 1);

    return dup;
}

FILE* fopen(const char* Path, const char* Mode)
{
    Args* args;
    FILE* fp;
    if (strstr(Path, "/dev"))
        return stdout;

    args = (Args*)OE_HostMalloc(sizeof(Args));
    args->path = OE_HostStackStrdup(Path);
    args->mode = OE_HostStackStrdup(Mode);

    OE_CallHost("OE_FOpen", args);
    fp = args->F_ptr;
    OE_HostFree(args);
    return fp;
}

int fclose(FILE* fp)
{
    int ret;
    Args* args;

    if ((fp == stdout) || (fp == stderr))
        return 0;

    args = (Args*)OE_HostMalloc(sizeof(Args));
    args->F_ptr = fp;
    OE_CallHost("OE_FClose", args);
    ret = args->ret;
    OE_HostFree(args);
    return ret;
}

int feof(FILE* fp)
{
    int ret;
    Args* args;
    args = (Args*)OE_HostMalloc(sizeof(Args));
    args->F_ptr = fp;
    OE_CallHost("OE_FEof", args);
    ret = args->ret;
    OE_HostFree(args);
    return ret;
}

char* fgets(char* buf, int len, FILE* fp)
{
    char* ret;
    Args* args;
    args = (Args*)OE_HostMalloc(sizeof(Args));
    args->F_ptr = fp;
    args->buf = (char*)OE_HostMalloc(len);
    args->len = len;
    OE_CallHost("OE_FGets", args);

    if (args->ptr != NULL)
    {
        OE_Memcpy(buf, args->buf, len);
    }
    ret = (char*)args->ptr;

    OE_HostFree(args->buf);
    OE_HostFree(args);
    return ret;
}

int fputc(int c, FILE* stream)
{
    int ret;
    Args* args;

    if (stream == stdout)
    {
        /* Write to standard output device */
        __OE_HostPrint(0, &c, 1);
        return c;
    }
    else if (stream == stderr)
    {
        /* Write to standard error device */
        __OE_HostPrint(1, (const char*)&c, 1);
        return c;
    }
    else
    {
        args = (Args*)OE_HostMalloc(sizeof(Args));
        args->F_ptr = stream;
        args->i_var = c;
        OE_CallHost("OE_FPutc", args);

        ret = args->ret;
        OE_HostFree(args);
        return ret;
    }
}

int fileno(FILE* stream)
{
    if (stream == stdout)
        return (int)stdout;
    else if (stream == stderr)
        return (int)stderr;
    else
        return 0;
}

int dup(int oldfd)
{
    if ((FILE*)oldfd == stdout)
        return (int)stdout;
    else if ((FILE*)oldfd == stderr)
        return (int)stderr;
    else
        return 0;
}

FILE* fdopen(int fd, const char* mode)
{
    if ((FILE*)fd == stdout)
        return stdout;
    else if ((FILE*)fd == stderr)
        return stderr;
    else
        return NULL;
}
