// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NO_POSIX_FILE_API
#include <openenclave/internal/fs.h>
#include <openenclave/libcex/stdio.h>
#include <stdarg.h>

void oe_clearerr(OE_FILE* stream)
{
    return clearerr((FILE*)stream);
}

int oe_fclose(OE_FILE* stream)
{
    return fclose((FILE*)stream);
}

OE_FILE* oe_fdopen(int fd, const char* mode)
{
    return (OE_FILE*)fdopen(fd, mode);
}

int oe_feof(OE_FILE* stream)
{
    return feof((FILE*)stream);
}

int oe_ferror(OE_FILE* stream)
{
    return ferror((FILE*)stream);
}

int oe_fflush(OE_FILE* stream)
{
    return fflush((FILE*)stream);
}

int oe_fgetc(OE_FILE* stream)
{
    return fgetc((FILE*)stream);
}

int oe_fgetpos(OE_FILE* stream, fpos_t* pos)
{
    return fgetpos((FILE*)stream, pos);
}

char* oe_fgets(char* s, int size, OE_FILE* stream)
{
    return fgets(s, size, (FILE*)stream);
}

int oe_fileno(OE_FILE* stream)
{
    return fileno((FILE*)stream);
}

OE_FILE* oe_fopen(uint64_t devid, const char* path, const char* mode)
{
    if (oe_mount(NULL, "__tls__", NULL, 0, &devid) != 0)
    {
        oe_errno = EINVAL;
        return NULL;
    }

    FILE* ret = (FILE*)fopen(path, mode);

    oe_umount("__tls__");

    return (OE_FILE*)ret;
}

int oe_fprintf(OE_FILE* stream, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfprintf((FILE*)stream, format, ap);
    va_end(ap);
    return n;
}

int oe_fputc(int c, OE_FILE* stream)
{
    return fputc(c, (FILE*)stream);
}

int oe_fputs(const char* s, OE_FILE* stream)
{
    return fputs(s, (FILE*)stream);
}

size_t oe_fread(void* ptr, size_t size, size_t nmemb, OE_FILE* stream)
{
    return fread(ptr, size, nmemb, (FILE*)stream);
}

OE_FILE* oe_freopen(const char* path, const char* mode, OE_FILE* stream)
{
    return (OE_FILE*)freopen(path, mode, (FILE*)stream);
}

int oe_fscanf(OE_FILE* stream, const char* format, ...)
{
    va_list ap;
    va_start(ap, format);
    int n = vfscanf((FILE*)stream, format, ap);
    va_end(ap);
    return n;
}

int oe_fseek(OE_FILE* stream, long offset, int whence)
{
    return fseek((FILE*)stream, offset, whence);
}

int oe_fseeko(OE_FILE* stream, off_t offset, int whence)
{
    return fseeko((FILE*)stream, offset, whence);
}

int oe_fsetpos(OE_FILE* stream, const fpos_t* pos)
{
    return fsetpos((FILE*)stream, pos);
}

long oe_ftell(OE_FILE* stream)
{
    return ftell((FILE*)stream);
}

long oe_ftello(OE_FILE* stream)
{
    return ftello((FILE*)stream);
}

size_t oe_fwrite(const void* ptr, size_t size, size_t nmemb, OE_FILE* stream)
{
    return fwrite(ptr, size, nmemb, (FILE*)stream);
}

int oe_getc(OE_FILE* stream)
{
    return getc((FILE*)stream);
}

int oe_putc(int c, OE_FILE* stream)
{
    return putc(c, (FILE*)stream);
}

void oe_rewind(OE_FILE* stream)
{
    return rewind((FILE*)stream);
}

void oe_setbuf(OE_FILE* stream, char* buf)
{
    return setbuf((FILE*)stream, buf);
}

int oe_setvbuf(OE_FILE* stream, char* buf, int mode, size_t size)
{
    return setvbuf((FILE*)stream, buf, mode, size);
}

int oe_ungetc(int c, OE_FILE* stream)
{
    return ungetc(c, (FILE*)stream);
}

int oe_vfprintf(OE_FILE* stream, const char* format, va_list ap)
{
    return vfprintf((FILE*)stream, format, ap);
}

int oe_vfscanf(OE_FILE* stream, const char* format, va_list ap)
{
    return vfscanf((FILE*)stream, format, ap);
}
