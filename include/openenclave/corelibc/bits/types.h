// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_BITS_TYPES_H
#define _OE_CORELIBC_BITS_TYPES_H

#include <openenclave/bits/types.h>

typedef uint32_t oe_mode_t;
typedef int64_t oe_off_t;
typedef uint64_t oe_ino_t;
typedef uint64_t oe_dev_t;
typedef uint32_t oe_gid_t;
typedef uint32_t oe_uid_t;
typedef int oe_pid_t;
typedef uint64_t oe_nlink_t;
typedef int64_t oe_blksize_t;
typedef int64_t oe_blkcnt_t;
typedef uint32_t oe_socklen_t;
typedef uint16_t oe_sa_family_t;
typedef uint16_t oe_in_port_t;
typedef uint32_t oe_in_addr_t;
typedef struct _OE_DIR OE_DIR;
struct oe_dirent;

#if defined(OE_NEED_STDC_NAMES)

typedef oe_mode_t mode_t;
typedef oe_off_t off_t;
typedef oe_ino_t ino_t;
typedef oe_dev_t dev_t;
typedef oe_gid_t gid_t;
typedef oe_uid_t uid_t;
typedef oe_pid_t pid_t;
typedef oe_nlink_t nlink_t;
typedef oe_blksize_t blksize_t;
typedef oe_blkcnt_t blkcnt_t;
typedef oe_socklen_t socklen_t;
typedef oe_sa_family_t sa_family_t;
typedef oe_in_port_t in_port_t;
typedef oe_in_addr_t in_addr_t;
typedef OE_DIR DIR;
struct dirent;

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_CORELIBC_BITS_TYPES_H */
