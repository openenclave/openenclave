#ifdef _XOPEN_SOURCE
#include <ftw.h>
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
T(struct FTW)
T(struct stat)
C(FTW_F)
C(FTW_D)
C(FTW_DNR)
C(FTW_DP)
C(FTW_NS)
C(FTW_SL)
C(FTW_SLN)
C(FTW_PHYS)
C(FTW_MOUNT)
C(FTW_DEPTH)
C(FTW_CHDIR)
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
C(S_ISVTX)
C(S_IFMT)
C(S_IFBLK)
C(S_IFCHR)
C(S_IFIFO)
C(S_IFREG)
C(S_IFDIR)
C(S_IFLNK)
C(S_IFSOCK)
C(S_ISBLK(0))
C(S_ISCHR(0))
C(S_ISDIR(0))
C(S_ISFIFO(0))
C(S_ISREG(0))
C(S_ISLNK(0))
C(S_ISSOCK(0))
{
struct FTW x;
F(int, base)
F(int, level)
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
}
{int(*p)(const char*,int(*)(const char*,const struct stat*,int),int) = ftw;}
{int(*p)(const char*,int(*)(const char*,const struct stat*,int,struct FTW*),int,int) = nftw;}
}
#endif

