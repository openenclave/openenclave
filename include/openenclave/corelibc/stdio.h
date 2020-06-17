// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_STDIO_H
#define _OE_STDIO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/stdfile.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/stdint.h>
#include <openenclave/internal/syscall/unistd.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

int oe_vsnprintf(char* str, size_t size, const char* format, oe_va_list ap);

OE_PRINTF_FORMAT(3, 4)
int oe_snprintf(char* str, size_t size, const char* format, ...);

int oe_vprintf(const char* format, oe_va_list ap);

OE_PRINTF_FORMAT(1, 2)
int oe_printf(const char* format, ...);

int oe_fputc(int c, OE_FILE* stream);

int oe_vfprintf(OE_FILE* stream, const char* format, oe_va_list ap);

OE_PRINTF_FORMAT(2, 3)
OE_INLINE int oe_fprintf(OE_FILE* stream, const char* format, ...)
{
    oe_va_list ap;
    oe_va_start(ap, format);
    int r = oe_vfprintf(stream, format, ap);
    oe_va_end(ap);

    return r;
}

int oe_rename(const char* oldpath, const char* newpath);

int oe_rename_d(uint64_t devid, const char* oldpath, const char* newpath);

OE_FILE* oe_fopen(const char* path, const char* mode);

int oe_fflush(OE_FILE* stream);

int oe_fclose(OE_FILE* stream);

size_t oe_fread(void* ptr, size_t size, size_t nmemb, OE_FILE* stream);

size_t oe_fwrite(const void* ptr, size_t size, size_t nmemb, OE_FILE* stream);

long oe_ftell(OE_FILE* stream);

OE_INLINE oe_off_t oe_ftello(OE_FILE* stream)
{
    return (oe_off_t)oe_ftell(stream);
}

int oe_fseek(OE_FILE* stream, long offset, int whence);

OE_INLINE int oe_fseeko(OE_FILE* stream, oe_off_t offset, int whence)
{
    return oe_fseek(stream, (long)offset, whence);
}

int oe_ferror(OE_FILE* stream);

int oe_feof(OE_FILE* stream);

void oe_clearerr(OE_FILE* stream);

int oe_fgetc(OE_FILE* stream);

char* oe_fgets(char* s, int size, OE_FILE* stream);

int oe_fileno(OE_FILE* stream);

OE_FILE* oe_fdopen(int fd, const char* mode);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define BUFSIZ OE_BUFSIZ
#define EOF (-1)

OE_INLINE int vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return oe_vsnprintf(str, size, format, ap);
}

#ifdef _MSC_VER
OE_INLINE int _vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    return oe_vsnprintf(str, size, format, ap);
}
#endif

OE_PRINTF_FORMAT(3, 4)
OE_INLINE
int snprintf(char* str, size_t size, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vsnprintf(str, size, format, ap);
    va_end(ap);
}

OE_PRINTF_FORMAT(2, 3)
OE_INLINE int sprintf(char* str, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vsnprintf(str, OE_SIZE_MAX, format, ap);
    va_end(ap);
}

OE_INLINE
int vprintf(const char* format, va_list ap)
{
    return oe_vprintf(format, ap);
}

OE_PRINTF_FORMAT(1, 2)
OE_INLINE
int printf(const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    return oe_vprintf(format, ap);
    va_end(ap);
}

OE_PRINTF_FORMAT(2, 3)
OE_INLINE int fprintf(FILE* stream, const char* format, ...)
{
    oe_va_list ap;
    oe_va_start(ap, format);
    return oe_vfprintf((OE_FILE*)stream, format, ap);
    oe_va_end(ap);
}

OE_INLINE int vfprintf(FILE* stream, const char* format, va_list ap)
{
    return oe_vfprintf((OE_FILE*)stream, format, ap);
}

OE_INLINE int rename(const char* oldpath, const char* newpath)
{
    return oe_rename(oldpath, newpath);
}

OE_INLINE FILE* fopen(const char* path, const char* mode)
{
    return (FILE*)oe_fopen(path, mode);
}

OE_INLINE int fflush(FILE* stream)
{
    return oe_fflush((OE_FILE*)stream);
}

OE_INLINE int fclose(FILE* stream)
{
    return oe_fclose((OE_FILE*)stream);
}

OE_INLINE size_t fread(void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return oe_fread(ptr, size, nmemb, (OE_FILE*)stream);
}

OE_INLINE size_t
fwrite(const void* ptr, size_t size, size_t nmemb, FILE* stream)
{
    return oe_fwrite(ptr, size, nmemb, (OE_FILE*)stream);
}

OE_INLINE long ftell(FILE* stream)
{
    return oe_ftell((OE_FILE*)stream);
}

OE_INLINE off_t ftello(FILE* stream)
{
    return oe_ftello((OE_FILE*)stream);
}

OE_INLINE int fseek(FILE* stream, long offset, int whence)
{
    return oe_fseek((OE_FILE*)stream, offset, whence);
}

OE_INLINE int fseeko(FILE* stream, off_t offset, int whence)
{
    return oe_fseeko((OE_FILE*)stream, offset, whence);
}

OE_INLINE int ferror(FILE* stream)
{
    return oe_ferror((OE_FILE*)stream);
}

OE_INLINE int feof(FILE* stream)
{
    return oe_feof((OE_FILE*)stream);
}

OE_INLINE void clearerr(FILE* stream)
{
    return oe_clearerr((OE_FILE*)stream);
}

OE_INLINE int fgetc(FILE* stream)
{
    return oe_fgetc((OE_FILE*)stream);
}

OE_INLINE char* fgets(char* s, int size, FILE* stream)
{
    return oe_fgets(s, size, (OE_FILE*)stream);
}

OE_INLINE int fileno(FILE* stream)
{
    return oe_fileno((OE_FILE*)stream);
}

OE_INLINE FILE* fdopen(int fd, const char* mode)
{
    return (FILE*)oe_fdopen(fd, mode);
}

OE_INLINE int fputc(int c, FILE* stream)
{
    return oe_fputc(c, (OE_FILE*)stream);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_STDIO_H */
