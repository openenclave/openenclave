#include <wchar.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
#ifdef _POSIX_C_SOURCE
T(FILE)
T(locale_t)
T(va_list)
#endif
T(mbstate_t)
T(size_t)
T(wchar_t)
T(wint_t)
T(struct tm)
C(WCHAR_MAX)
C(WCHAR_MIN)
C(WEOF)
{void *x=NULL;}
{wint_t(*p)(int) = btowc;}
{wint_t(*p)(FILE*) = fgetwc;}
{wchar_t*(*p)(wchar_t*restrict,int,FILE*restrict) = fgetws;}
{wint_t(*p)(wchar_t,FILE*) = fputwc;}
{int(*p)(const wchar_t*restrict,FILE*restrict) = fputws;}
{int(*p)(FILE*,int) = fwide;}
{int(*p)(FILE*restrict,const wchar_t*restrict,...) = fwprintf;}
{int(*p)(FILE*restrict,const wchar_t*restrict,...) = fwscanf;}
{wint_t(*p)(FILE*) = getwc;}
{wint_t(*p)(void) = getwchar;}
{size_t(*p)(const char*restrict,size_t,mbstate_t*restrict) = mbrlen;}
{size_t(*p)(wchar_t*restrict,const char*restrict,size_t,mbstate_t*restrict) = mbrtowc;}
{int(*p)(const mbstate_t*) = mbsinit;}
{size_t(*p)(wchar_t*restrict,const char**restrict,size_t,mbstate_t*restrict) = mbsrtowcs;}
{wint_t(*p)(wchar_t,FILE*) = putwc;}
{wint_t(*p)(wchar_t) = putwchar;}
{int(*p)(wchar_t*restrict,size_t,const wchar_t*restrict,...) = swprintf;}
{int(*p)(const wchar_t*restrict,const wchar_t*restrict,...) = swscanf;}
{wint_t(*p)(wint_t,FILE*) = ungetwc;}
{int(*p)(FILE*restrict,const wchar_t*restrict,va_list) = vfwprintf;}
{int(*p)(FILE*restrict,const wchar_t*restrict,va_list) = vfwscanf;}
{int(*p)(wchar_t*restrict,size_t,const wchar_t*restrict,va_list) = vswprintf;}
{int(*p)(const wchar_t*restrict,const wchar_t*restrict,va_list) = vswscanf;}
{int(*p)(const wchar_t*restrict,va_list) = vwprintf;}
{int(*p)(const wchar_t*restrict,va_list) = vwscanf;}
{size_t(*p)(char*restrict,wchar_t,mbstate_t*restrict) = wcrtomb;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict) = wcscat;}
{wchar_t*(*p)(const wchar_t*,wchar_t) = wcschr;}
{int(*p)(const wchar_t*,const wchar_t*) = wcscmp;}
{int(*p)(const wchar_t*,const wchar_t*) = wcscoll;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict) = wcscpy;}
{size_t(*p)(const wchar_t*,const wchar_t*) = wcscspn;}
{size_t(*p)(wchar_t*restrict,size_t,const wchar_t*restrict,const struct tm*restrict) = wcsftime;}
{size_t(*p)(const wchar_t*) = wcslen;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict,size_t) = wcsncat;}
{int(*p)(const wchar_t*,const wchar_t*,size_t) = wcsncmp;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict,size_t) = wcsncpy;}
{wchar_t*(*p)(const wchar_t*,const wchar_t*) = wcspbrk;}
{wchar_t*(*p)(const wchar_t*,wchar_t) = wcsrchr;}
{size_t(*p)(char*restrict,const wchar_t**restrict,size_t,mbstate_t*restrict) = wcsrtombs;}
{size_t(*p)(const wchar_t*,const wchar_t*) = wcsspn;}
{wchar_t*(*p)(const wchar_t*restrict,const wchar_t*restrict) = wcsstr;}
{double(*p)(const wchar_t*restrict,wchar_t**restrict) = wcstod;}
{float(*p)(const wchar_t*restrict,wchar_t**restrict) = wcstof;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict,wchar_t**restrict) = wcstok;}
{long(*p)(const wchar_t*restrict,wchar_t**restrict,int) = wcstol;}
{long double(*p)(const wchar_t*restrict,wchar_t**restrict) = wcstold;}
{long long(*p)(const wchar_t*restrict,wchar_t**restrict,int) = wcstoll;}
{unsigned long(*p)(const wchar_t*restrict,wchar_t**restrict,int) = wcstoul;}
{unsigned long long(*p)(const wchar_t*restrict,wchar_t**restrict,int) = wcstoull;}
{size_t(*p)(wchar_t*restrict,const wchar_t*restrict,size_t) = wcsxfrm;}
{int(*p)(wint_t) = wctob;}
{wchar_t*(*p)(const wchar_t*,wchar_t,size_t) = wmemchr;}
{int(*p)(const wchar_t*,const wchar_t*,size_t) = wmemcmp;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict,size_t) = wmemcpy;}
{wchar_t*(*p)(wchar_t*,const wchar_t*,size_t) = wmemmove;}
{wchar_t*(*p)(wchar_t*,wchar_t,size_t) = wmemset;}
#ifdef _POSIX_C_SOURCE
{size_t(*p)(wchar_t*restrict,const char**restrict,size_t,size_t,mbstate_t*restrict) = mbsnrtowcs;}
{FILE*(*p)(wchar_t**,size_t*) = open_wmemstream;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict) = wcpcpy;}
{wchar_t*(*p)(wchar_t*restrict,const wchar_t*restrict,size_t) = wcpncpy;}
{int(*p)(const wchar_t*,const wchar_t*) = wcscasecmp;}
{int(*p)(const wchar_t*,const wchar_t*,locale_t) = wcscasecmp_l;}
{int(*p)(const wchar_t*,const wchar_t*,locale_t) = wcscoll_l;}
{wchar_t*(*p)(const wchar_t*) = wcsdup;}
{int(*p)(const wchar_t*,const wchar_t*,size_t) = wcsncasecmp;}
{int(*p)(const wchar_t*,const wchar_t*,size_t,locale_t) = wcsncasecmp_l;}
{size_t(*p)(const wchar_t*,size_t) = wcsnlen;}
{size_t(*p)(char*restrict,const wchar_t**restrict,size_t,size_t,mbstate_t*restrict) = wcsnrtombs;}
{size_t(*p)(wchar_t*restrict,const wchar_t*restrict,size_t,locale_t) = wcsxfrm_l;}
#endif
#ifdef _XOPEN_SOURCE
{int(*p)(const wchar_t*,size_t) = wcswidth;}
{int(*p)(wchar_t) = wcwidth;}
#endif
}
