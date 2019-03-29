// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_STAT_H
#define _OE_SYS_STAT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

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

struct oe_stat
{
#include <openenclave/corelibc/bits/struct_stat.h>
};

#ifndef st_atime
#define st_atime st_atim.tv_sec
#endif

#ifndef st_ctime
#define st_mtime st_mtim.tv_sec
#endif

#ifndef st_ctime
#define st_ctime st_ctim.tv_sec
#endif

int oe_stat(const char* pathname, struct oe_stat* buf);

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat* buf);

int oe_mkdir(const char* pathname, mode_t mode);

int oe_mkdir_d(uint64_t devid, const char* pathname, mode_t mode);

#if defined(OE_NEED_STDC_NAMES)

#define S_IFMT OE_S_IFMT
#define S_IFDIR OE_S_IFDIR
#define S_IFCHR OE_S_IFCHR
#define S_IFBLK OE_S_IFBLK
#define S_IFREG OE_S_IFREG
#define S_IFIFO OE_S_IFIFO
#define S_IFLNK OE_S_IFLNK
#define S_IFSOCK OE_S_IFSOCK

#define S_ISDIR(mode) OE_S_ISDIR(mode)
#define S_ISCHR(mode) OE_S_ISCHR(mode)
#define S_ISBLK(mode) OE_S_ISBLK(mode)
#define S_ISREG(mode) OE_S_ISREG(mode)
#define S_ISFIFO(mode) OE_S_ISFIFO(mode)
#define S_ISLNK(mode) OE_S_ISLNK(mode)
#define S_ISSOCK(mode) OE_S_ISSOCK(mode)
#define S_ISUID(mode) OE_S_ISUID(mode)
#define S_ISGID(mode) OE_S_ISGID(mode)
#define S_ISVTX(mode) OE_S_ISVTX(mode)

#define S_IRUSR OE_S_IRUSR
#define S_IWUSR OE_S_IWUSR
#define S_IXUSR OE_S_IXUSR
#define S_IRGRP OE_S_IRGRP
#define S_IWGRP OE_S_IWGRP
#define S_IXGRP OE_S_IXGRP
#define S_IROTH OE_S_IROTH
#define S_IWOTH OE_S_IWOTH
#define S_IXOTH OE_S_IXOTH
#define S_IRWXUSR OE_S_IRWXUSR
#define S_IRWXGRP OE_S_IRWXGRP
#define S_IRWXOTH OE_S_IRWXOTH
#define S_IRWUSR OE_S_IRWUSR
#define S_IRWGRP OE_S_IRWGRP
#define S_IRWOTH OE_S_IRWOTH

struct stat
{
#include <openenclave/corelibc/bits/struct_stat.h>
};

OE_INLINE int stat(const char* pathname, struct stat* buf)
{
    return oe_stat(pathname, (struct oe_stat*)buf);
}

OE_INLINE int mkdir(const char* pathname, mode_t mode)
{
    return oe_mkdir(pathname, mode);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_STAT_H */
