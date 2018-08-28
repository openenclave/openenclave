#include <monetary.h>
#define T(t) (t*)0;
static void f()
{
T(locale_t)
T(size_t)
T(ssize_t)
{ssize_t(*p)(char*restrict,size_t,const char*restrict,...) = strfmon;}
{ssize_t(*p)(char*restrict,size_t,locale_t,const char*restrict,...) = strfmon_l;}
}
