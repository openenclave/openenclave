#include <poll.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(nfds_t)
{
struct pollfd x;
F(int, fd)
F(short, events)
F(short, revents)
}
C(POLLIN)
C(POLLRDNORM)
C(POLLRDBAND)
C(POLLPRI)
C(POLLOUT)
C(POLLWRNORM)
C(POLLWRBAND)
C(POLLERR)
C(POLLHUP)
C(POLLNVAL)
{int(*p)(struct pollfd[],nfds_t,int) = poll;}
}
