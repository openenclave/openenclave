#include <iconv.h>
#define T(t) (t*)0;
static void f()
{
T(iconv_t)
T(size_t)
{size_t(*p)(iconv_t,char**restrict,size_t*restrict,char**restrict,size_t*restrict) = iconv;}
{int(*p)(iconv_t) = iconv_close;}
{iconv_t(*p)(const char*,const char*) = iconv_open;}
}
