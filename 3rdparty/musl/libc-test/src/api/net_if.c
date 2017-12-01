#include <net/if.h>
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
{
struct if_nameindex x;
F(unsigned, if_index)
F(char*, if_name)
}
C(IF_NAMESIZE)
{void(*p)(struct if_nameindex*) = if_freenameindex;}
{char*(*p)(unsigned,char*) = if_indextoname;}
{struct if_nameindex*(*p)(void) = if_nameindex;}
{unsigned(*p)(const char*) = if_nametoindex;}
}
