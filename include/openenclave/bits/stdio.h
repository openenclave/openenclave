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
    OE_FILE_SECURE_HARDWARE = 1,     /** Inaccessible from normal world. */
    OE_FILE_SECURE_ENCRYPTION = 2,
} oe_file_security_t;

#ifdef OE_USE_OPTEE
# define OE_FILE_SECURE_BEST_EFFORT OE_FILE_SECURE_HARDWARE
#else
# define OE_FILE_SECURE_BEST_EFFORT OE_FILE_SECURE_ENCRYPTION
#endif

#define OE_CAT(a, ...) OE_PRIMITIVE_CAT(a, __VA_ARGS__)
#define OE_PRIMITIVE_CAT(a, ...) a ## __VA_ARGS__

typedef struct oe_file OE_FILE;
typedef struct oe_dir OE_DIR;

int oe_fclose(OE_FILE* stream);
int oe_feof(OE_FILE* stream);
int oe_ferror(OE_FILE* stream);
int oe_fflush(OE_FILE* stream);
char *oe_fgets(char* s, int size, OE_FILE* stream);
int oe_fprintf(OE_FILE* const stream, char const* const format, ...);
int oe_fputs(const char* s, OE_FILE* stream);
size_t oe_fread(void* ptr, size_t size, size_t nmemb, OE_FILE* stream);
int oe_fseek(OE_FILE* stream, long offset, int whence);
long oe_ftell(OE_FILE* stream);
int oe_vfprintf(OE_FILE* stream, const char* format, va_list argptr);
size_t oe_fwrite(const void* ptr, size_t size, size_t nmemb, OE_FILE* stream);

OE_FILE* oe_fopen_OE_FILE_INSECURE(const char* path, const char* mode);
OE_FILE* oe_fopen_OE_FILE_SECURE_HARDWARE(const char* path, const char* mode);
OE_FILE* oe_fopen_OE_FILE_SECURE_ENCRYPTION(const char* path, const char* mode);

int oe_remove_OE_FILE_INSECURE(const char* pathname);
int oe_remove_OE_FILE_SECURE_HARDWARE(const char* pathname);
int oe_remove_OE_FILE_SECURE_ENCRYPTION(const char* pathname);

#define oe_fopen(file_security, path, mode)  OE_PRIMITIVE_CAT(oe_fopen_, file_security((path), (mode)))
#define oe_remove(file_security, pathname)   OE_PRIMITIVE_CAT(oe_remove_, file_security(pathname))

#ifdef OE_SECURE_POSIX_FILE_API
#define fopen(path, mode) oe_fopen(OE_FILE_SECURE_BEST_EFFORT, path, mode)
#define remove(pathname) oe_remove(OE_FILE_SECURE_BEST_EFFORT, pathname)
#elif !defined(OE_NO_POSIX_FILE_API)
#define fopen(path, mode) oe_fopen(OE_FILE_INSECURE, path, mode)
#define remove(pathname) oe_remove(OE_FILE_INSECURE, pathname)
#endif

#ifndef OE_NO_POSIX_FILE_API
/* Map POSIX API names to the OE equivalents. */
# define fclose   oe_fclose
# define feof     oe_feof
# define ferror   oe_ferror
# define fflush   oe_fflush
# define fread    oe_fread
# define fseek    oe_fseek
# define ftell    oe_ftell
# define fwrite   oe_fwrite
# define fprintf  oe_fprintf
# define fputs    oe_fputs
# define fgets    oe_fgets
# define vfprintf oe_vfprintf
# define FILE     OE_FILE
#endif

OE_DIR *oe_opendir_FILE_INSECURE(const char *name);
OE_DIR *oe_opendir_SECURE_HARDWARE(const char *name);
OE_DIR *oe_opendir_SECURE_ENCRYPTION(const char *name);

#define oe_opendir(file_security, name) oe_opendir_ ## file_security(name)

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

#if !defined(_FILE_DEFINED) && !defined(_STDIO_H)
# define stdin ((void*)0)
# define stdout ((void*)1)
# define stderr ((void*)2)

# define _FILE_DEFINED
#endif

#if !defined(STDIO_H) && !defined(_STDIO_H)
int printf(const char* fmt, ...);
#endif

int vprintf(const char* format, va_list argptr);

typedef struct {
    int (*f_fclose)(intptr_t stream);
    int (*f_feof)(intptr_t stream);
    int (*f_ferror)(intptr_t stream);
    int (*f_fflush)(intptr_t stream);
    char* (*f_fgets)(char* str, int n, intptr_t stream);
    int (*f_fputs)(const char* str, intptr_t stream);
    size_t (*f_fread)(void* buffer, size_t size, size_t count, intptr_t stream);
    int (*f_fseek)(intptr_t stream, long offset, int origin);
    long (*f_ftell)(intptr_t stream);
    size_t (*f_fwrite)(const void* buffer, size_t size, size_t count, intptr_t stream);
} oe_file_provider_t;

OE_FILE* oe_register_stream(
    const oe_file_provider_t* provider,
    intptr_t stream);
