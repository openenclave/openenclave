#include <sys/un.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
static void f()
{
T(sa_family_t)
{
struct sockaddr_un x;
F(sa_family_t,sun_family)
F(char, sun_path[0])
}
}

