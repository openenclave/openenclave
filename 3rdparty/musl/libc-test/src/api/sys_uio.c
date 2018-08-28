#include <sys/uio.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
static void f()
{
T(size_t)
T(ssize_t)
{
struct iovec x;
F(void *,iov_base)
F(size_t,iov_len)
}
{ssize_t(*p)(int,const struct iovec*,int) = readv;}
{ssize_t(*p)(int,const struct iovec*,int) = writev;}
}
