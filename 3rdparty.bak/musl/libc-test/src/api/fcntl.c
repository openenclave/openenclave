#include <fcntl.h>
#include "options.h"
#define T(t) (t*)0;
#define F(t,n) {t *y = &x.n;}
#define C(n) switch(n){case n:;}
static void f()
{
C(F_DUPFD)
C(F_DUPFD_CLOEXEC)
C(F_GETFD)
C(F_SETFD)
C(F_GETFL)
C(F_SETFL)
C(F_GETLK)
C(F_SETLK)
C(F_SETLKW)
C(F_GETOWN)
C(F_SETOWN)
C(FD_CLOEXEC)
C(F_RDLCK)
C(F_UNLCK)
C(F_WRLCK)
C(SEEK_SET)
C(SEEK_CUR)
C(SEEK_END)
C(O_CREAT)
C(O_EXCL)
C(O_NOCTTY)
C(O_TRUNC)
C(O_TTY_INIT)
C(O_APPEND)
C(O_NONBLOCK)
#ifdef POSIX_SYNCHRONIZED_IO
C(O_DSYNC)
C(O_RSYNC)
#endif
C(O_SYNC)
C(O_ACCMODE)
C(O_EXEC)
C(O_RDONLY)
C(O_RDWR)
C(O_SEARCH)
C(O_WRONLY)
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
#endif
C(AT_FDCWD)
C(AT_EACCESS)
C(AT_SYMLINK_NOFOLLOW)
C(AT_SYMLINK_FOLLOW)
C(O_CLOEXEC)
C(O_DIRECTORY)
C(O_NOFOLLOW)
C(AT_REMOVEDIR)
C(POSIX_FADV_DONTNEED)
C(POSIX_FADV_NOREUSE)
C(POSIX_FADV_NORMAL)
C(POSIX_FADV_RANDOM)
C(POSIX_FADV_SEQUENTIAL)
C(POSIX_FADV_WILLNEED)

{
struct flock x;
F(short, l_type)
F(short, l_whence)
F(off_t, l_start)
F(off_t, l_len)
F(pid_t, l_pid)
}

T(mode_t)
T(off_t)
T(pid_t)

{int(*p)(int,int,...) = fcntl;}
{int(*p)(int,off_t,off_t,int) = posix_fadvise;}
{int(*p)(int,off_t,off_t) = posix_fallocate;}
}
#ifndef _XOPEN_SOURCE
#include <sys/stat.h>
#endif
static void g()
{
{int(*p)(const char*,mode_t) = creat;}
{int(*p)(const char*,int,...) = open;}
{int(*p)(int,const char*,int,...) = openat;}
}
