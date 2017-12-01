#include <strings.h>
#define T(t) (t*)0;
static void f()
{
T(size_t)
T(locale_t)
#ifdef _XOPEN_SOURCE
{int(*p)(int) = ffs;}
#endif
{int(*p)(const char*,const char*) = strcasecmp;}
{int(*p)(const char*,const char*,locale_t) = strcasecmp_l;}
{int(*p)(const char*,const char*,size_t) = strncasecmp;}
{int(*p)(const char*,const char*,size_t,locale_t) = strncasecmp_l;}
}
