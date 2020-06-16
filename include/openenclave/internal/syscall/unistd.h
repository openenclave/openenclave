// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_UNISTD_H
#define _OE_SYSCALL_UNISTD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/time.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/stdarg.h>
#include <openenclave/internal/syscall/unistd.h>

OE_EXTERNC_BEGIN

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

oe_off_t oe_lseek(int fd, oe_off_t offset, int whence);

ssize_t oe_pread(int fd, void* buf, size_t count, oe_off_t offset);

ssize_t oe_pwrite(int fd, const void* buf, size_t count, oe_off_t offset);

int oe_truncate(const char* path, oe_off_t length);

int oe_truncate_d(uint64_t devid, const char* path, oe_off_t length);

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

int oe_gethostname(char* name, size_t len);

int oe_getdomainname(char* name, size_t len);

unsigned int oe_sleep(unsigned int seconds);

int oe_nanosleep(struct oe_timespec* req, struct oe_timespec* rem);

int oe_flock(int fd, int operation);

int oe_dup(int fd);

int oe_dup2(int fd, int newfd);

oe_pid_t oe_getpid(void);

oe_pid_t oe_getppid(void);

oe_pid_t oe_getpgrp(void);

oe_uid_t oe_getuid(void);

oe_uid_t oe_geteuid(void);

oe_gid_t oe_getgid(void);

oe_gid_t oe_getegid(void);

oe_pid_t oe_getpgid(oe_pid_t pid);

int oe_getgroups(int size, oe_gid_t list[]);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_UNISTD_H */
