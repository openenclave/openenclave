#include <sys/utsname.h>
#define F(t,n) {t *y = &x.n;}
static void f()
{
{
struct utsname x;
F(char,sysname[1])
F(char,nodename[1])
F(char,release[1])
F(char,version[1])
F(char,machine[1])
}
{int(*p)(struct utsname*) = uname;}
}
