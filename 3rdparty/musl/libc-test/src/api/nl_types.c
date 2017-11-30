#include <nl_types.h>
#define T(t) (t*)0;
#define C(n) switch(n){case n:;}
static void f()
{
T(nl_catd)
T(nl_item)
C(NL_SETD)
C(NL_CAT_LOCALE)
{int(*p)(nl_catd) = catclose;}
{char*(*p)(nl_catd,int,int,const char*) = catgets;}
{nl_catd(*p)(const char*,int) = catopen;}
}
