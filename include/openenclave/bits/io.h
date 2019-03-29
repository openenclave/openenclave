// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_IO_H
#define _OE_BITS_IO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define OE_DEVID_NULL ((uint64_t)0)
#define OE_DEVID_HOSTFS ((uint64_t)1)
#define OE_DEVID_SGXFS ((uint64_t)2)
#define OE_DEVID_SHWFS ((uint64_t)3)
#define OE_DEVID_HOST_SOCKET ((uint64_t)4)
#define OE_DEVID_ENCLAVE_SOCKET ((uint64_t)5)
#define OE_DEVID_EPOLL ((uint64_t)6)
#define OE_DEVID_EVENTFD ((uint64_t)7)
#define OE_DEVID_HARDWARE_SECURE_SOCKET ((uint64_t)8)

typedef struct _OE_DIR OE_DIR;
struct oe_dirent;
struct oe_stat;

int oe_open_d(uint64_t devid, const char* pathname, int flags, mode_t mode);

int oe_rename_d(uint64_t devid, const char* oldpath, const char* newpath);

int oe_access_d(uint64_t devid, const char* pathname, int mode);

int oe_link_d(uint64_t devid, const char* oldpath, const char* newpath);

int oe_unlink_d(uint64_t devid, const char* pathname);

int oe_rmdir_d(uint64_t devid, const char* pathname);

int oe_truncate_d(uint64_t devid, const char* path, off_t length);

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname);

int oe_socket_d(uint64_t devid, int domain, int type, int protocol);

int oe_stat_d(uint64_t devid, const char* pathname, struct oe_stat* buf);

int oe_mkdir_d(uint64_t devid, const char* pathname, mode_t mode);

OE_EXTERNC_END

#endif /* _OE_BITS_IO_H */
