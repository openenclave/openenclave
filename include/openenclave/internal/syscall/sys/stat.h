// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_STAT_H
#define _OE_SYSCALL_SYS_STAT_H

#include <openenclave/corelibc/bits/types.h>
#include <openenclave/internal/bits/fcntl.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

#define OE_S_IFMT 0170000
#define OE_S_IFDIR 0040000
#define OE_S_IFCHR 0020000
#define OE_S_IFBLK 0060000
#define OE_S_IFREG 0100000
#define OE_S_IFIFO 0010000
#define OE_S_IFLNK 0120000
#define OE_S_IFSOCK 0140000

#define OE_S_ISDIR(mode) (((mode)&OE_S_IFMT) == OE_S_IFDIR)
#define OE_S_ISCHR(mode) (((mode)&OE_S_IFMT) == OE_S_IFCHR)
#define OE_S_ISBLK(mode) (((mode)&OE_S_IFMT) == OE_S_IFBLK)
#define OE_S_ISREG(mode) (((mode)&OE_S_IFMT) == OE_S_IFREG)
#define OE_S_ISFIFO(mode) (((mode)&OE_S_IFMT) == OE_S_IFIFO)
#define OE_S_ISLNK(mode) (((mode)&OE_S_IFMT) == OE_S_IFLNK)
#define OE_S_ISSOCK(mode) (((mode)&OE_S_IFMT) == OE_S_IFSOCK)

#define OE_S_ISUID 0x0800
#define OE_S_ISGID 0x0400
#define OE_S_ISVTX 0x0200
#define OE_S_IRUSR 0x0100
#define OE_S_IWUSR 0x0080
#define OE_S_IXUSR 0x0040
#define OE_S_IRGRP 0x0020
#define OE_S_IWGRP 0x0010
#define OE_S_IXGRP 0x0008
#define OE_S_IROTH 0x0004
#define OE_S_IWOTH 0x0002
#define OE_S_IXOTH 0x0001
#define OE_S_IRWXUSR (OE_S_IRUSR | OE_S_IWUSR | OE_S_IXUSR)
#define OE_S_IRWXGRP (OE_S_IRGRP | OE_S_IWGRP | OE_S_IXGRP)
#define OE_S_IRWXOTH (OE_S_IROTH | OE_S_IWOTH | OE_S_IXOTH)
#define OE_S_IRWUSR (OE_S_IRUSR | OE_S_IWUSR)
#define OE_S_IRWGRP (OE_S_IRGRP | OE_S_IWGRP)
#define OE_S_IRWOTH (OE_S_IROTH | OE_S_IWOTH)

OE_STATIC_ASSERT((sizeof(struct oe_stat_t) % 8) == 0);
OE_STATIC_ASSERT(sizeof(struct oe_stat_t) == 120);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_dev) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_ino) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_nlink) == 16);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_mode) == 24);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_uid) == 28);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_gid) == 32);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_rdev) == 40);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_size) == 48);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_blksize) == 56);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_blocks) == 64);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_atim.tv_sec) == 72);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_atim.tv_nsec) == 80);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_mtim.tv_sec) == 88);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_mtim.tv_nsec) == 96);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_ctim.tv_sec) == 104);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_stat_t, st_ctim.tv_nsec) == 112);

#define OE_R_OR 04
#define OE_W_OR 02
#define OE_X_OR 01

#ifndef st_atime
#define st_atime st_atim.tv_sec
#endif

#ifndef st_ctime
#define st_mtime st_mtim.tv_sec
#endif

#ifndef st_ctime
#define st_ctime st_ctim.tv_sec
#endif

int oe_stat(const char* pathname, struct oe_stat_t* buf);

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat_t* buf);

int oe_fstat(int fd, struct oe_stat_t* buf);

int oe_mkdir(const char* pathname, oe_mode_t mode);

int oe_mkdir_d(uint64_t devid, const char* pathname, oe_mode_t mode);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_STAT_H */
