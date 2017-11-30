#include <stdio.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(FILE)
T(fpos_t)
T(off_t)
T(size_t)
C(BUFSIZ)
#ifdef _POSIX_C_SOURCE
T(ssize_t)
T(va_list)
C(L_ctermid)
#endif
#ifdef OBSOLETE
C(L_tmpnam)
#endif
C(_IOFBF)
C(_IOLBF)
C(_IONBF)
C(SEEK_CUR)
C(SEEK_END)
C(SEEK_SET)
C(FILENAME_MAX)
C(FOPEN_MAX)
C(EOF)
{void *x=NULL;}
{FILE *x=stderr;}
{FILE *x=stdin;}
{FILE *x=stdout;}
{void(*p)(FILE*) = clearerr;}
{char*(*p)(char*) = ctermid;}
{int(*p)(int,const char*restrict,...) = dprintf;}
{int(*p)(FILE*) = fclose;}
{FILE*(*p)(int,const char*) = fdopen;}
{int(*p)(FILE*) = feof;}
{int(*p)(FILE*) = ferror;}
{int(*p)(FILE*) = fflush;}
{int(*p)(FILE*) = fgetc;}
{int(*p)(FILE*restrict,fpos_t*restrict) = fgetpos;}
{char*(*p)(char*restrict,int,FILE*restrict) = fgets;}
{int(*p)(FILE*) = fileno;}
{void(*p)(FILE*) = flockfile;}
{FILE*(*p)(void*restrict,size_t,const char*restrict) = fmemopen;}
{FILE*(*p)(const char*restrict,const char*restrict) = fopen;}
{int(*p)(FILE*restrict,const char*restrict,...) = fprintf;}
{int(*p)(int,FILE*) = fputc;}
{int(*p)(const char*restrict,FILE*restrict) = fputs;}
{size_t(*p)(void*restrict,size_t,size_t,FILE*restrict) = fread;}
{FILE*(*p)(const char*restrict,const char*restrict,FILE*restrict) = freopen;}
{int(*p)(FILE*restrict,const char*restrict,...) = fscanf;}
{int(*p)(FILE*,long,int) = fseek;}
{int(*p)(FILE*,off_t,int) = fseeko;}
{int(*p)(FILE*,const fpos_t*) = fsetpos;}
{long(*p)(FILE*) = ftell;}
{off_t(*p)(FILE*) = ftello;}
{int(*p)(FILE*) = ftrylockfile;}
{void(*p)(FILE*) = funlockfile;}
{size_t(*p)(const void*restrict,size_t,size_t,FILE*restrict) = fwrite;}
{int(*p)(FILE*) = getc;}
{int(*p)(FILE*) = getc_unlocked;}
{int(*p)(void) = getchar;}
{int(*p)(void) = getchar_unlocked;}
{ssize_t(*p)(char**restrict,size_t*restrict,int,FILE*restrict) = getdelim;}
{ssize_t(*p)(char**restrict,size_t*restrict,FILE*restrict) = getline;}
{char*(*p)(char*) = gets;}
{FILE*(*p)(char**,size_t*) = open_memstream;}
{int(*p)(FILE*) = pclose;}
{void(*p)(const char*) = perror;}
{FILE*(*p)(const char*,const char*) = popen;}
{int(*p)(const char*restrict,...) = printf;}
{int(*p)(int,FILE*) = putc;}
{int(*p)(int,FILE*) = putc_unlocked;}
{int(*p)(int) = putchar;}
{int(*p)(int) = putchar_unlocked;}
{int(*p)(const char*) = puts;}
{int(*p)(const char*) = remove;}
{int(*p)(const char*,const char*) = rename;}
{int(*p)(int,const char*,int,const char*) = renameat;}
{void(*p)(FILE*) = rewind;}
{int(*p)(const char*restrict,...) = scanf;}
{void(*p)(FILE*restrict,char*restrict) = setbuf;}
{int(*p)(FILE*restrict,char*restrict,int,size_t) = setvbuf;}
{int(*p)(char*restrict,size_t,const char*restrict,...) = snprintf;}
{int(*p)(char*restrict,const char*restrict,...) = sprintf;}
{int(*p)(const char*restrict,const char*restrict,...) = sscanf;}
{char*(*p)(const char*,const char*) = tempnam;}
{FILE*(*p)(void) = tmpfile;}
{char*(*p)(char*) = tmpnam;}
{int(*p)(int,FILE*) = ungetc;}
}
#include <wchar.h>
static void g()
{
{wint_t(*p)(int) = btowc;}
{wint_t(*p)(FILE*) = fgetwc;}
{wchar_t*(*p)(wchar_t*restrict,int,FILE*restrict) = fgetws;}
{wint_t(*p)(wchar_t,FILE*) = fputwc;}
{int(*p)(const wchar_t*restrict,FILE*restrict) = fputws;}
{int(*p)(FILE*,int) = fwide;}
{int(*p)(FILE*restrict,const wchar_t*restrict,...) = fwprintf;}
{int(*p)(FILE*restrict,const wchar_t*restrict,...) = fwscanf;}
{wint_t(*p)(FILE*) = getwc;}
{wint_t(*p)(wchar_t,FILE*) = putwc;}
{int(*p)(wchar_t*restrict,size_t,const wchar_t*restrict,...) = swprintf;}
{int(*p)(const wchar_t*restrict,const wchar_t*restrict,...) = swscanf;}
{wint_t(*p)(wint_t,FILE*) = ungetwc;}
{int(*p)(wint_t) = wctob;}
{int(*p)(const wchar_t*restrict,...) = wprintf;}
{int(*p)(const wchar_t*restrict,...) = wscanf;}
}
#include <stdarg.h>
static void h()
{
{int(*p)(int,const char*restrict,va_list) = vdprintf;}
{int(*p)(FILE*restrict,const char*restrict,va_list) = vfprintf;}
{int(*p)(FILE*restrict,const char*restrict,va_list) = vfscanf;}
{int(*p)(const char*restrict,va_list) = vprintf;}
{int(*p)(const char*restrict,va_list) = vscanf;}
{int(*p)(char*restrict,size_t,const char*restrict,va_list) = vsnprintf;}
{int(*p)(char*restrict,const char*restrict,va_list) = vsprintf;}
{int(*p)(const char*restrict,const char*restrict,va_list) = vsscanf;}

{int(*p)(FILE*restrict,const wchar_t*restrict,va_list) = vfwprintf;}
{int(*p)(FILE*restrict,const wchar_t*restrict,va_list) = vfwscanf;}
{int(*p)(wchar_t*restrict,size_t,const wchar_t*restrict,va_list) = vswprintf;}
{int(*p)(const wchar_t*restrict,const wchar_t*restrict,va_list) = vswscanf;}
{int(*p)(const wchar_t*restrict,va_list) = vwprintf;}
{int(*p)(const wchar_t*restrict,va_list) = vwscanf;}
}
