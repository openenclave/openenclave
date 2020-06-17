// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_DIRENT_H
#define _OE_SYSCALL_DIRENT_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/bits/types.h>
#include <openenclave/corelibc/limits.h>
#include <openenclave/internal/bits/fcntl.h>

OE_EXTERNC_BEGIN

/* struct dirent d_type values. */
#define OE_DT_UNKNOWN 0
#define OE_DT_FIFO 1
#define OE_DT_CHR 2
#define OE_DT_DIR 4
#define OE_DT_BLK 6
#define OE_DT_REG 8
#define OE_DT_LNK 10
#define OE_DT_SOCK 12
#define OE_DT_WHT 14

typedef struct _OE_DIR OE_DIR;

OE_DIR* oe_opendir(const char* pathname);

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname);

struct oe_dirent* oe_readdir(OE_DIR* dir);

void oe_rewinddir(OE_DIR* dir);

int oe_closedir(OE_DIR* dir);

int oe_getdents64(unsigned int fd, struct oe_dirent* dirp, unsigned int count);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_DIRENT_H */
