#include <sys/statvfs.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(fsblkcnt_t)
T(fsfilcnt_t)
{
struct statvfs x;
F(unsigned long, f_bsize)
F(unsigned long, f_frsize)
F(fsblkcnt_t,f_blocks)
F(fsblkcnt_t,f_bfree)
F(fsblkcnt_t,f_bavail)
F(fsfilcnt_t,f_files)
F(fsfilcnt_t,f_ffree)
F(fsfilcnt_t,f_favail)
F(unsigned long, f_fsid)
F(unsigned long, f_flag)
F(unsigned long, f_namemax)
}
C(ST_RDONLY)
C(ST_NOSUID)
{int(*p)(int,struct statvfs*) = fstatvfs;}
{int(*p)(const char*restrict,struct statvfs*restrict) = statvfs;}
}
