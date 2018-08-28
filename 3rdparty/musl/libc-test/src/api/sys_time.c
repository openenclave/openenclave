#include <sys/time.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(time_t)
T(suseconds_t)
T(fd_set)
{
struct timeval x;
F(time_t, tv_sec)
F(suseconds_t,tv_usec)
}
C(FD_SETSIZE)
#ifndef FD_CLR
{void(*p)(int,fd_set*) = FD_CLR;}
#endif
#ifndef FD_ISSET
{int(*p)(int,fd_set*) = FD_ISSET;}
#endif
#ifndef FD_SET
{void(*p)(int,fd_set*) = FD_SET;}
#endif
#ifndef FD_ZERO
{void(*p)(fd_set*) = FD_ZERO;}
#endif
{int(*p)(int,fd_set*restrict,fd_set*restrict,fd_set*restrict,struct timeval*restrict) = select;}
{int(*p)(const char*,const struct timeval[]) = utimes;}
}
