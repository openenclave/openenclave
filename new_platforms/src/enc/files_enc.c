/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#define OE_NO_POSIX_FILE_API
#include <openenclave/bits/stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    intptr_t provider_stream;
    const oe_file_provider_t* provider;
} oe_internal_file_t;

OE_FILE* oe_register_stream(
    const oe_file_provider_t* provider,
    intptr_t stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)malloc(sizeof(*fp));
    if (fp == NULL) {
        return NULL;
    }
    fp->provider = provider;
    fp->provider_stream = stream;
    return (OE_FILE*)fp;
}

int oe_fclose(OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    int result = fp->provider->f_fclose(fp->provider_stream);
    free(fp);
    return result;
}

int oe_feof(
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_feof(fp->provider_stream);
}

int oe_ferror(
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_ferror(fp->provider_stream);
}

int oe_fflush(
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_fflush(fp->provider_stream);
}

char* oe_fgets(
    char* str,
    int n,
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_fgets(str, n, fp->provider_stream);
}

int oe_fputs(const char* str, OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    if (fp->provider->f_fputs != NULL) {
        return fp->provider->f_fputs(str, fp->provider_stream);
    }

    /* Default to implementing fputs over fwrite. */
    size_t bytesToWrite = strlen(str);
    size_t bytesWritten = oe_fwrite(str, 1, bytesToWrite, stream);
    return (bytesWritten == bytesToWrite) ? 0 : -1;
}

size_t oe_fread(
    void* buffer,
    size_t size,
    size_t count,
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_fread(buffer, size, count, fp->provider_stream);
}

int oe_fseek(
    OE_FILE* stream,
    long offset,
    int origin)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_fseek(fp->provider_stream, offset, origin);
}

long oe_ftell(
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_ftell(fp->provider_stream);
}

size_t oe_fwrite(
    const void* buffer,
    size_t size,
    size_t count,
    OE_FILE* stream)
{
    oe_internal_file_t* fp = (oe_internal_file_t*)stream;
    return fp->provider->f_fwrite(buffer, size, count, fp->provider_stream);
}
