#include <sys/stat.h>
#include "options.h"
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(blkcnt_t)
T(blksize_t)
T(dev_t)
T(ino_t)
T(mode_t)
T(nlink_t)
T(uid_t)
T(gid_t)
T(off_t)
T(time_t)
{
struct timespec x;
F(time_t,tv_sec)
F(long,tv_nsec)
}
{
struct stat x;
F(dev_t, st_dev)
F(ino_t, st_ino)
F(mode_t, st_mode)
F(nlink_t, st_nlink)
F(uid_t, st_uid)
F(gid_t, st_gid)
F(dev_t, st_rdev)
F(off_t, st_size)
F(struct timespec, st_atim)
F(struct timespec, st_mtim)
F(struct timespec, st_ctim)
F(blksize_t, st_blksize)
F(blkcnt_t, st_blocks)

F(time_t, st_atime)
F(time_t, st_mtime)
F(time_t, st_ctime)
}
C(S_IRWXU)
C(S_IRUSR)
C(S_IWUSR)
C(S_IXUSR)
C(S_IRWXG)
C(S_IRGRP)
C(S_IWGRP)
C(S_IXGRP)
C(S_IRWXO)
C(S_IROTH)
C(S_IWOTH)
C(S_IXOTH)
C(S_ISUID)
C(S_ISGID)
#ifdef _XOPEN_SOURCE
C(S_ISVTX)
C(S_IFMT)
C(S_IFBLK)
C(S_IFCHR)
C(S_IFIFO)
C(S_IFREG)
C(S_IFDIR)
C(S_IFLNK)
C(S_IFSOCK)
#endif
C(S_ISBLK(0))
C(S_ISCHR(0))
C(S_ISDIR(0))
C(S_ISFIFO(0))
C(S_ISREG(0))
C(S_ISLNK(0))
C(S_ISSOCK(0))
{
struct stat x = {0};
{int i = S_TYPEISMQ(&x);}
{int i = S_TYPEISSEM(&x);}
{int i = S_TYPEISSHM(&x);}
#ifdef POSIX_TYPED_MEMORY_OBJECTS
{int i = S_TYPEISTMO(&x);}
#endif
}
C(UTIME_NOW)
C(UTIME_OMIT)
{int(*p)(const char*,mode_t) = chmod;}
{int(*p)(int,mode_t) = fchmod;}
{int(*p)(int,const char*,mode_t,int) = fchmodat;}
{int(*p)(int,struct stat*) = fstat;}
{int(*p)(int,const char*restrict,struct stat*restrict,int) = fstatat;}
{int(*p)(int,const struct timespec[]) = futimens;}
{int(*p)(const char*restrict,struct stat*restrict) = lstat;}
{int(*p)(const char*,mode_t) = mkdir;}
{int(*p)(int,const char*,mode_t) = mkdirat;}
{int(*p)(const char*,mode_t) = mkfifo;}
{int(*p)(int,const char*,mode_t) = mkfifoat;}
#ifdef _XOPEN_SOURCE
{int(*p)(const char*,mode_t,dev_t) = mknod;}
{int(*p)(int,const char*,mode_t,dev_t) = mknodat;}
#endif
{int(*p)(const char*restrict,struct stat*restrict) = stat;}
{mode_t(*p)(mode_t) = umask;}
{int(*p)(int,const char*,const struct timespec[],int) = utimensat;}
}
