// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <stdio.h>
#include <string.h>
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

char* oe_host_stack_strdup(const char* str)
{
    size_t n = oe_strlen(str);

    char* dup = (char*)oe_host_malloc(n + 1);

    if (dup)
        oe_memcpy(dup, str, n + 1);

    return dup;
}

FILE* fopen(const char* Path, const char* Mode)
{
    Args* args;
    FILE* fp;

    // Assume that all file paths starting with "/dev/*" can be redirected to
    // stdout.
    // This includes devices that may not be /dev/tty* or /dev/console.
    if (strstr(Path, "/dev/") == Path)
        return stdout;

    args = (Args*)oe_host_malloc(sizeof(Args));
    args->path = oe_host_stack_strdup(Path);
    args->mode = oe_host_stack_strdup(Mode);

    oe_call_host("mbed_test_fopen", args);
    fp = args->F_ptr;
    oe_host_free(args);
    return fp;
}

int fclose(FILE* fp)
{
    int ret;
    Args* args;

    if ((fp == stdout) || (fp == stderr))
        return 0;

    args = (Args*)oe_host_malloc(sizeof(Args));
    args->F_ptr = fp;
    oe_call_host("mbed_test_fclose", args);
    ret = args->ret;
    oe_host_free(args);
    return ret;
}

int feof(FILE* fp)
{
    int ret;
    Args* args;
    args = (Args*)oe_host_malloc(sizeof(Args));
    args->F_ptr = fp;
    oe_call_host("mbed_test_feof", args);
    ret = args->ret;
    oe_host_free(args);
    return ret;
}

char* fgets(char* buf, int len, FILE* fp)
{
    char* ret;
    Args* args;
    args = (Args*)oe_host_malloc(sizeof(Args));
    args->F_ptr = fp;
    args->buf = (char*)oe_host_malloc(len);
    args->len = len;
    oe_call_host("mbed_test_fgets", args);

    if (args->ptr != NULL)
    {
        oe_memcpy(buf, args->buf, len);
    }
    ret = (char*)args->ptr;

    oe_host_free(args->buf);
    oe_host_free(args);
    return ret;
}

// Necessary with Clang in Release mode.
char* fgets_unlocked(char* buf, int len, FILE* fp)
{
    return fgets(buf, len, fp);
}

int fputc(int c, FILE* stream)
{
    int ret;
    Args* args;

    if (stream == stdout)
    {
        /* Write to standard output device */
        __oe_host_print(0, &c, 1);
        return c;
    }
    else if (stream == stderr)
    {
        /* Write to standard error device */
        __oe_host_print(1, (const char*)&c, 1);
        return c;
    }
    else
    {
        args = (Args*)oe_host_malloc(sizeof(Args));
        args->F_ptr = stream;
        args->i_var = c;
        oe_call_host("mbed_test_fputc", args);

        ret = args->ret;
        oe_host_free(args);
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
