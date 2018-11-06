/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef TRUSTED_CODE
# error tcps_stdio_t.h should only be included with TRUSTED_CODE
#endif
#define _NO_CRT_STDIO_INLINE
#include <stdio.h>
#include "oeenclave.h"

#if defined(USE_SGX)

# include <sgx_tprotected_fs.h>
# include <stdarg.h>
# define FILE SGX_FILE

#elif defined(USE_OPTEE)

# include <tee_api.h>
# include <inttypes.h>
# define FILE OPTEE_FILE
# define _FILE _OPTEE_FILE

typedef struct _OPTEE_FILE {
    TEE_ObjectHandle hObject;
    int iEof;
    int iError;
} OPTEE_FILE;

#ifndef SEEK_SET
# define SEEK_SET TEE_DATA_SEEK_SET
#endif
#ifndef SEEK_END
# define SEEK_END TEE_DATA_SEEK_END
#endif

#else
# error define USE_SGX or USE_OPTEE
#endif /* USE_OPTEE */

#define ENOENT     2
#define ENOMEM    12
#define EACCES    13
#define EEXIST    17
#define EINVAL    22
#define ERANGE    34

#ifndef _FILE_DEFINED
# define stdin ((void*)0)
# define stdout ((void*)1)
# define stderr ((void*)2)

int fclose(
    FILE* stream);

int feof(
    FILE* stream);

int ferror(
    FILE* stream);

char* fgets(
    char* str,
    int n,
    FILE* stream);

int fflush(
    FILE* stream);

FILE* fopen(
    const char* filename,
    const char* mode);

int fprintf(FILE* const _Stream, char const* const _Format, ...);

int fputs(const char* str, FILE* stream);

size_t fread(
    void* buffer,
    size_t size,
    size_t count,
    FILE* stream);

int fseek(
    FILE* stream,
    long offset,
    int origin);

long ftell(
    FILE* stream);

size_t fwrite(
    const void* buffer,
    size_t size,
    size_t count,
    FILE* stream);

int vfprintf(
    FILE* stream,
    const char* format,
    va_list argptr);

# define _FILE_DEFINED
#endif

#ifndef STDIO_H
int printf(const char* fmt, ...);
#endif

int vprintf(const char* format, va_list argptr);
