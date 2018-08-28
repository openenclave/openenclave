#include <string.h>
#define T(t) (t*)0;
static void f()
{
T(size_t)
{void *x=NULL;}
{void*(*p)(const void*,int,size_t) = memchr;}
{int(*p)(const void*,const void*,size_t) = memcmp;}
{void*(*p)(void*restrict,const void*restrict,size_t) = memcpy;}
{void*(*p)(void*,const void*,size_t) = memmove;}
{void*(*p)(void*,int,size_t) = memset;}
{char*(*p)(char*restrict,const char*restrict) = strcat;}
{char*(*p)(const char*,int) = strchr;}
{int(*p)(const char*,const char*) = strcmp;}
{int(*p)(const char*,const char*) = strcoll;}
{char*(*p)(char*restrict,const char*restrict) = strcpy;}
{size_t(*p)(const char*,const char*) = strcspn;}
{char*(*p)(int) = strerror;}
{size_t(*p)(const char*) = strlen;}
{char*(*p)(char*restrict,const char*restrict,size_t) = strncat;}
{int(*p)(const char*,const char*,size_t) = strncmp;}
{char*(*p)(char*restrict,const char*restrict,size_t) = strncpy;}
{char*(*p)(const char*,const char*) = strpbrk;}
{char*(*p)(const char*,int) = strrchr;}
{char*(*p)(int) = strsignal;}
{size_t(*p)(const char*,const char*) = strspn;}
{char*(*p)(const char*,const char*) = strstr;}
{char*(*p)(char*restrict,const char*restrict) = strtok;}
{size_t(*p)(char*restrict,const char*restrict,size_t) = strxfrm;}
#ifdef _POSIX_C_SOURCE
T(locale_t)
{char*(*p)(char*restrict,const char*restrict) = stpcpy;}
{char*(*p)(char*restrict,const char*restrict,size_t) = stpncpy;}
{int(*p)(const char*,const char*,locale_t) = strcoll_l;}
{char*(*p)(const char*) = strdup;}
{char*(*p)(int,locale_t) = strerror_l;}
{int(*p)(int,char*,size_t) = strerror_r;}
{char*(*p)(const char*,size_t) = strndup;}
{size_t(*p)(const char*,size_t) = strnlen;}
{char*(*p)(char*restrict,const char*restrict,char**restrict) = strtok_r;}
{size_t(*p)(char*restrict,const char*restrict,size_t,locale_t) = strxfrm_l;}
#endif
#ifdef _XOPEN_SOURCE
{void*(*p)(void*restrict,const void*restrict,int,size_t) = memccpy;}
#endif
}
