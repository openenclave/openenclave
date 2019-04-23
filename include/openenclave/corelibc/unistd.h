// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_UNISTD_H
#define _OE_UNISTD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/corelibc/unistd.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe-prefixed names:
**
**==============================================================================
*/

#define OE_STDIN_FILENO 0
#define OE_STDOUT_FILENO 1
#define OE_STDERR_FILENO 2

/* access() mode flags. */
#define OE_F_OK 0
#define OE_R_OK 4
#define OE_W_OK 2
#define OE_X_OK 1

/* lseek() whence parameters. */
#define OE_SEEK_SET 0
#define OE_SEEK_CUR 1
#define OE_SEEK_END 2

#define OE_NGROUP_MAX 256

int oe_access(const char* pathname, int mode);

int oe_access_d(uint64_t devid, const char* pathname, int mode);

void* oe_sbrk(intptr_t increment);

ssize_t oe_read(int fd, void* buf, size_t count);

ssize_t oe_write(int fd, const void* buf, size_t count);

#if !defined(WIN32) /* __feature_io__ */

off_t oe_lseek(int fd, off_t offset, int whence);

int oe_truncate(const char* path, off_t length);

int oe_truncate_d(uint64_t devid, const char* path, off_t length);

#endif /* !defined(WIN32) */

int oe_link(const char* oldpath, const char* newpath);

int oe_link_d(uint64_t devid, const char* oldpath, const char* newpath);

int oe_unlink(const char* pathname);

int oe_unlink_d(uint64_t devid, const char* pathname);

int oe_rmdir(const char* pathname);

int oe_rmdir_d(uint64_t devid, const char* pathname);

char* oe_getcwd(char* buf, size_t size);

int oe_chdir(const char* path);

int oe_close(int fd);

int __oe_fcntl(int fd, int cmd, uint64_t arg);

#if !defined(WIN32) /* __feature_io__ */
OE_INLINE int oe_fcntl(int fd, int cmd, ...)
{
    oe_va_list ap;
    oe_va_start(ap, cmd);
    int r = __oe_fcntl(fd, cmd, oe_va_arg(ap, uint64_t));
    oe_va_end(ap);

    return r;
}
#endif /* !defined(WIN32) */

int oe_gethostname(char* name, size_t len);

int oe_getdomainname(char* name, size_t len);

unsigned int oe_sleep(unsigned int seconds);

int oe_dup(int fd);

int oe_dup2(int fd, int newfd);

pid_t oe_getpid(void);

pid_t oe_getppid(void);

pid_t oe_getpgrp(void);

uid_t oe_getuid(void);

uid_t oe_geteuid(void);

gid_t oe_getgid(void);

gid_t oe_getegid(void);

pid_t oe_getpgid(pid_t pid);

int oe_getgroups(int size, gid_t list[]);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define STDIN_FILENO OE_STDIN_FILENO
#define STDOUT_FILENO OE_STDOUT_FILENO
#define STDERR_FILENO OE_STDERR_FILENO
#define F_OK OE_F_OK
#define R_OK OE_R_OK
#define W_OK OE_W_OK
#define X_OK OE_X_OK
#define SEEK_SET OE_SEEK_SET
#define SEEK_CUR OE_SEEK_CUR
#define SEEK_END OE_SEEK_END

OE_INLINE void* sbrk(intptr_t increment)
{
    return oe_sbrk(increment);
}

OE_INLINE ssize_t read(int fd, void* buf, size_t count)
{
    return oe_read(fd, buf, count);
}

OE_INLINE ssize_t write(int fd, const void* buf, size_t count)
{
    return oe_write(fd, buf, count);
}

OE_INLINE int access(const char* pathname, int mode)
{
    return oe_access(pathname, mode);
}

OE_INLINE off_t lseek(int fd, off_t offset, int whence)
{
    return oe_lseek(fd, offset, whence);
}

OE_INLINE int link(const char* oldpath, const char* newpath)
{
    return oe_link(oldpath, newpath);
}

OE_INLINE int unlink(const char* pathname)
{
    return oe_unlink(pathname);
}

OE_INLINE int rmdir(const char* pathname)
{
    return oe_rmdir(pathname);
}

OE_INLINE int truncate(const char* path, off_t length)
{
    return oe_truncate(path, length);
}

OE_INLINE char* getcwd(char* buf, size_t size)
{
    return oe_getcwd(buf, size);
}

OE_INLINE int chdir(const char* path)
{
    return oe_chdir(path);
}

OE_INLINE int close(int fd)
{
    return oe_close(fd);
}

OE_INLINE int gethostname(char* name, size_t len)
{
    return oe_gethostname(name, len);
}

OE_INLINE int getdomainname(char* name, size_t len)
{
    return oe_getdomainname(name, len);
}

OE_INLINE unsigned int sleep(unsigned int seconds)
{
    return oe_sleep(seconds);
}

OE_INLINE int fcntl(int fd, int cmd, ...)
{
    oe_va_list ap;
    oe_va_start(ap, cmd);
    int r = __oe_fcntl(fd, cmd, oe_va_arg(ap, uint64_t));
    oe_va_end(ap);

    return r;
}

OE_INLINE int dup(int fd)
{
    return oe_dup(fd);
}

OE_INLINE int dup2(int fd, int newfd)
{
    return oe_dup2(fd, newfd);
}

OE_INLINE pid_t getpid(void)
{
    return oe_getpid();
}

OE_INLINE pid_t getppid(void)
{
    return oe_getppid();
}

OE_INLINE pid_t getpgrp(void)
{
    return oe_getpgrp();
}

OE_INLINE uid_t getuid(void)
{
    return oe_getuid();
}

OE_INLINE uid_t geteuid(void)
{
    return oe_geteuid();
}

OE_INLINE gid_t getgid(void)
{
    return oe_getgid();
}

OE_INLINE gid_t getegid(void)
{
    return oe_getegid();
}

OE_INLINE pid_t getpgid(pid_t pid)
{
    return oe_getpgid(pid);
}

OE_INLINE int getgroups(int size, gid_t list[])
{
    return oe_getgroups(size, list);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_UNISTD_H */
