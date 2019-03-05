/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _LIBCEX_STDIO_H
#define _LIBCEX_STDIO_H

#if defined(_MSC_VER)
#define _NO_CRT_STDIO_INLINE
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/devids.h>
#include <openenclave/internal/fs.h>
#include <openenclave/libcex/bits/common.h>
#include <stdio.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe-prefixed standard stream I/O functions (the "oe" namespace).
**
**==============================================================================
*/

typedef struct _OE_IO_FILE OE_FILE;

void oe_clearerr(OE_FILE* stream);

int oe_fclose(OE_FILE* stream);

OE_FILE* oe_fdopen(int fd, const char* mode);

int oe_feof(OE_FILE* stream);

int oe_ferror(OE_FILE* stream);

int oe_fflush(OE_FILE* stream);

int oe_fgetc(OE_FILE* stream);

int oe_fgetpos(OE_FILE* stream, fpos_t* pos);

char* oe_fgets(char* s, int size, OE_FILE* stream);

int oe_fileno(OE_FILE* stream);

OE_FILE* oe_fopen(uint64_t devid, const char* path, const char* mode);

int oe_fprintf(OE_FILE* stream, const char* format, ...);

int oe_fputc(int c, OE_FILE* stream);

int oe_fputs(const char* s, OE_FILE* stream);

size_t oe_fread(void* ptr, size_t size, size_t nmemb, OE_FILE* stream);

OE_FILE* oe_freopen(const char* path, const char* mode, OE_FILE* stream);

int oe_fscanf(OE_FILE* stream, const char* format, ...);

int oe_fseek(OE_FILE* stream, long offset, int whence);

int oe_fseeko(OE_FILE* stream, off_t offset, int whence);

int oe_fsetpos(OE_FILE* stream, const fpos_t* pos);

long oe_ftell(OE_FILE* stream);

long oe_ftello(OE_FILE* stream);

size_t oe_fwrite(const void* ptr, size_t size, size_t nmemb, OE_FILE* stream);

int oe_getc(OE_FILE* stream);

int oe_putc(int c, OE_FILE* stream);

void oe_rewind(OE_FILE* stream);

void oe_setbuf(OE_FILE* stream, char* buf);

int oe_setvbuf(OE_FILE* stream, char* buf, int mode, size_t size);

int oe_ungetc(int c, OE_FILE* stream);

int oe_vfprintf(OE_FILE* stream, const char* format, va_list ap);

int oe_vfscanf(OE_FILE* stream, const char* format, va_list ap);

/*
**==============================================================================
**
** Libc extensions:
**
**==============================================================================
*/

OE_INLINE OE_FILE* oe_fopen_nonsecure(const char* path, const char* mode)
{
    return oe_fopen(OE_DEVID_HOSTFS, path, mode);
}

OE_INLINE OE_FILE* oe_fopen_secure_encrypted(const char* path, const char* mode)
{
    return oe_fopen(OE_DEVID_SGXFS, path, mode);
}

OE_INLINE OE_FILE* oe_fopen_secure_hardware(const char* path, const char* mode)
{
    return oe_fopen(OE_DEVID_SHWFS, path, mode);
}

OE_INLINE OE_FILE* oe_fopen_secure(const char* path, const char* mode)
{
    /* Default to the secure file system for this platform. */
#ifdef OE_USE_OPTEE
    return oe_fopen_secure_hardware(path, mode);
#else
    return oe_fopen_secure_encrypted(path, mode);
#endif
}

OE_INLINE int oe_remove_nonsecure(const char* pathname)
{
    return oe_unlink_d(OE_DEVID_HOSTFS, pathname);
}

OE_INLINE int oe_remove_secure_encrypted(const char* pathname)
{
    return oe_unlink_d(OE_DEVID_SGXFS, pathname);
}

OE_INLINE int oe_remove_secure_hardware(const char* pathname)
{
    return oe_unlink_d(OE_DEVID_SHWFS, pathname);
}

OE_INLINE int oe_remove_secure(const char* pathname)
{
    /* Default to the secure file system for this platform. */
#ifdef OE_USE_OPTEE
    return oe_remove_secure_hardware(pathname);
#else
    return oe_remove_secure_encrypted(pathname);
#endif
}

#ifndef OE_NO_POSIX_FILE_API
#define clearerr oe_clearerr
#define fclose oe_fclose
#define fdopen oe_fdopen
#define feof oe_feof
#define ferror oe_ferror
#define fflush oe_fflush
#define fgetc oe_fgetc
#define fgetpos oe_fgetpos
#define fgets oe_fgets
#define fileno oe_fileno
#define fopen oe_fopen_secure
#define fprintf oe_fprintf
#define fputc oe_fputc
#define fputs oe_fputs
#define fread oe_fread
#define freopen oe_freopen
#define fscanf oe_fscanf
#define fseek oe_fseek
#define fseeko oe_fseeko
#define fsetpos oe_fsetpos
#define ftell oe_ftell
#define ftello oe_ftello
#define fwrite oe_fwrite
#define getc oe_getc
#define putc oe_putc
#define rewind oe_rewind
#define remove oe_remove_secure
#define setbuf oe_setbuf
#define setvbuf oe_setvbuf
#define ungetc oe_ungetc
#define vfprintf oe_vfprintf
#define vfscanf oe_vfscanf
#define FILE OE_FILE
#endif

OE_EXTERNC_END

#endif /* _LIBCEX_STDIO_H */
