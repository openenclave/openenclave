/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#define _NO_CRT_STDIO_INLINE
#include <stdio.h>
#ifndef _OE_ENCLAVE_H
# error openenclave/bits/stdio.h should only be included with enclave.h
#endif

typedef enum {
    OE_FILE_INSECURE = 0,
    OE_FILE_SECURE_HARDWARE = 1,
    OE_FILE_SECURE_ENCRYPTION = 2,
    OE_FILE_SECURE_BEST_EFFORT = 3,  /** Hardware if it exists, else encryption. */
} oe_file_security_t;

typedef struct oe_file OE_FILE;
typedef struct oe_dir OE_DIR;

int oe_fclose(OE_FILE* stream);
int oe_feof(OE_FILE* stream);
int oe_ferror(OE_FILE *stream);
int oe_fflush(OE_FILE *stream);
char *oe_fgets(char *s, int size, OE_FILE *stream);
OE_FILE *oe_fopen(oe_file_security_t file_security, const char* path, const char* mode);
int oe_fputs(const char *s, OE_FILE *stream);
size_t oe_fread(void *ptr, size_t size, size_t nmemb, OE_FILE *stream);
int oe_fseek(OE_FILE *stream, long offset, int whence);
long oe_ftell(OE_FILE *stream);
size_t oe_fwrite(const void *ptr, size_t size, size_t nmemb, OE_FILE *stream);
int oe_remove(oe_file_security_t file_security, const char *pathname);

#ifdef OE_SECURE_POSIX_FILE_API
#define fopen(path, mode) oe_fopen(OE_FILE_SECURE_BEST_EFFORT, path, mode)
#define remove(pathname) oe_remove(OE_FILE_SECURE_BEST_EFFORT, pathname)
#elif !defined(OE_NO_POSIX_FILE_API)
#define fopen(path, mode) oe_fopen(OE_FILE_INSECURE, path, mode)
#define remove(pathname) oe_remove(OE_FILE_INSECURE, pathname)
#endif

#ifndef OE_NO_POSIX_FILE_API
/* Map POSIX API names to the OE equivalents. */
# define fclose oe_fclose
# define feof   oe_feof
# define ferror oe_ferror
# define fflush oe_fflush
# define fread  oe_fread
# define fseek  oe_fseek
# define ftell  oe_ftell
# define fwrite oe_fwrite
# define fputs  oe_fputs
# define fgets  oe_fgets
# define FILE   OE_FILE
#endif

OE_DIR *oe_opendir(oe_file_security_t file_security, const char *name);

#ifdef OE_SECURE_POSIX_FILE_API
#define opendir(name) \
    oe_opendir(OE_FILE_SECURE_BEST_EFFORT, name)
#elif !defined(OE_NO_POSIX_FILE_API)
#define opendir(name) \
    oe_opendir(OE_FILE_INSECURE, name)
#endif

int oe_closedir(OE_DIR *dirp);
struct oe_dirent *oe_readdir(OE_DIR *dirp);


#if defined(OE_USE_OPTEE)

#ifndef SEEK_SET
# define SEEK_SET TEE_DATA_SEEK_SET
#endif
#ifndef SEEK_END
# define SEEK_END TEE_DATA_SEEK_END
#endif

#endif /* OE_USE_OPTEE */

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

int fprintf(FILE* const _Stream, char const* const _Format, ...);

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
