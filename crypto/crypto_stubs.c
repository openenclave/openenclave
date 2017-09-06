#include <sys/types.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <dlfcn.h>

/* Stubs for OpenSSL crypto library */

char* __crypto_getenv(const char* name);
char* __crypto_getenv(const char* name)
{
    return NULL;
}

pid_t __crypto_getpid(void);
pid_t __crypto_getpid(void)
{
    assert("__crypto_getpid() panic" == NULL);
    return 0;
}

int __crypto_fseek(FILE *stream, long offset, int whence);
int __crypto_fseek(FILE *stream, long offset, int whence)
{
    assert("__crypto_fseek() panic" == NULL);
    return -1;
}

char *__crypto_fgets(char *s, int size, FILE *stream);
char *__crypto_fgets(char *s, int size, FILE *stream)
{
    assert("__crypto_fgets() panic" == NULL);
    return NULL;
}

int __crypto_feof(FILE *stream);
int __crypto_feof(FILE *stream)
{
    assert("__crypto_feof() panic" == NULL);
    return -1;
}

long __crypto_ftell(FILE *stream);
long __crypto_ftell(FILE *stream)
{
    assert("__crypto_ftell() panic" == NULL);
    return -1;
}

int __crypto_fclose(FILE *stream);
int __crypto_fclose(FILE *stream)
{
    assert("__crypto_fclose() panic" == NULL);
    return -1;
}

int __crypto_fflush(FILE *stream);
int __crypto_fflush(FILE *stream)
{
    assert("__crypto_fflush() panic" == NULL);
    return -1;
}

size_t __crypto_fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __crypto_fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    assert("__crypto_fread() panic" == NULL);
    return 0;
}

int __crypto_ferror(FILE *stream);
int __crypto_ferror(FILE *stream)
{
    assert("__crypto_ferror() panic" == NULL);
    return 0;
}

struct tm *__crypto_localtime(const time_t *timep);
struct tm *__crypto_localtime(const time_t *timep)
{
    assert("__crypto_localtime() panic" == NULL);
    return NULL;
}

FILE *__crypto_fopen64(const char *path, const char *mode);
FILE *__crypto_fopen64(const char *path, const char *mode)
{
    assert("__crypto_fopen64() panic" == NULL);
    return NULL;
}

void *__crypto_dlopen(const char *filename, int flags);
void *__crypto_dlopen(const char *filename, int flags)
{
    assert("__crypto_dlopen() panic" == NULL);
    return NULL;
}

int __crypto_dlclose(void *handle);
int __crypto_dlclose(void *handle)
{
    assert("__crypto_dlclose() panic" == NULL);
    return -1;
}

void *__crypto_dlsym(void *handle, const char *symbol);
void *__crypto_dlsym(void *handle, const char *symbol)
{
    assert("__crypto_dlsym() panic" == NULL);
    return NULL;
}

char *__crypto_dlerror(void);
char *__crypto_dlerror(void)
{
    assert("__crypto_dlerror() panic" == NULL);
    return NULL;
}

int __crypto_dladdr(void *addr, Dl_info *info);
int __crypto_dladdr(void *addr, Dl_info *info)
{
    assert("__crypto_dladdr() panic" == NULL);
    return -1;
}

int __crypto_sprintf(char *str, const char *format, ...);
int __crypto_sprintf(char *str, const char *format, ...)
{
    if (!str)
        return 0;

    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(str, SIZE_MAX, format, ap);
    va_end(ap);
    return n;
}
