#ifndef __ELIBC_STDIO_H
#define __ELIBC_STDIO_H

#include <features.h>
#include <bits/alltypes.h>
#include <stdint.h>

__ELIBC_BEGIN

#define BUFSIZ 1024
#define EOF (-1)
#define WEOF 0xffffffffU

typedef uint64_t fpos_t;

typedef struct _IO_FILE FILE;

extern FILE* stdin;
extern FILE* stdout;
extern FILE* stderr;

int puts(const char *s);

int printf(const char *format, ...);

__attribute__((format(printf, 2, 3)))
int fprintf(FILE *stream, const char *format, ...);

__attribute__((format(printf, 3, 4)))
int snprintf(char *str, size_t size, const char *format, ...);

int vsnprintf(char *str, size_t size, const char *format, va_list ap);

int vasprintf(char **strp, const char *fmt, va_list ap);

int asprintf(char **strp, const char *fmt, ...);

int sscanf(const char *s, const char *fmt, ...);

int sscanf_l(const char *s, locale_t loc, const char *fmt, ...);

int vsscanf(const char *str, const char *format, va_list ap);

#ifdef __ELIBC_UNSUPPORTED
__attribute__((format(printf, 2, 3)))
int fprintf(FILE* stream, const char* fmt, ...);
#endif

#ifdef __ELIBC_UNSUPPORTED
int vfprintf(FILE *stream, const char *format, va_list ap);
#endif

#ifdef __ELIBC_UNSUPPORTED
int fputs(const char *s, FILE *stream);
#endif

#ifdef __ELIBC_UNSUPPORTED
FILE *fopen(const char *path, const char *mode);
#endif

#ifdef __ELIBC_UNSUPPORTED
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
#endif

#ifdef __ELIBC_UNSUPPORTED
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
#endif

#ifdef __ELIBC_UNSUPPORTED
int fclose(FILE *stream);
#endif

__ELIBC_END

#endif /* __ELIBC_STDIO_H */
