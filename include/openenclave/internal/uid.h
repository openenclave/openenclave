// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_UID_H
#define _OE_UID_H

#include <openenclave/bits/defs.h>

#define OE_NGROUP_MAX 256

OE_EXTERNC_BEGIN

typedef uint64_t oe_uid_t;
typedef uint64_t oe_gid_t;
typedef uint64_t oe_pid_t;

// enclave side
oe_pid_t oe_getpid(void);
oe_pid_t oe_getppid(void);
oe_pid_t oe_getpgrp(void);
oe_uid_t oe_getuid(void);
oe_uid_t oe_geteuid(void);

// host side
oe_pid_t oe_get_host_pid(void);
oe_pid_t oe_get_host_ppid(void);
oe_pid_t oe_get_host_pgrp(void);
oe_uid_t oe_get_host_uid(void);
oe_uid_t oe_get_host_euid(void);
int32_t oe_get_host_groups(size_t size, oe_gid_t list[]);

OE_EXTERNC_END

#endif /* _OE_UID_H */
