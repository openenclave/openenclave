#ifndef __OE_CRYPTO_STUBS_H
#define __OE_CRYPTO_STUBS_H

#define getenv __crypto_getenv

#define getpid __crypto_getpid

#define fseek __crypto_fseek
#define feof __crypto_feof
#define fclose __crypto_fclose
#define fflush __crypto_fflush
#define fread __crypto_fread
#define ferror __crypto_ferror
#define fgets __crypto_fgets
#define ftell __crypto_ftell
#define fopen __crypto_fopen

#define localtime __crypto_localtime

typedef struct _IO_FILE FILE;

extern FILE *__crypto_fopen64(const char *path, const char *mode);

inline FILE *fopen64(const char *path, const char *mode)
{
    return __crypto_fopen64(path, mode);
}

#define dlopen __crypto_dlopen
#define dlclose __crypto_dlclose
#define dlsym __crypto_dlsym
#define dlerror __crypto_dlerror
#define dladdr __crypto_dladdr

#define sprintf __crypto_sprintf

#endif /* __OE_CRYPTO_STUBS_H */
