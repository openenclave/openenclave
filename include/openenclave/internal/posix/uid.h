// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_UID_H
#define _OE_INTERNAL_POSIX_UID_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

pid_t oe_get_host_pid(void);

pid_t oe_get_host_ppid(void);

pid_t oe_get_host_pgrp(void);

uid_t oe_get_host_uid(void);

uid_t oe_get_host_euid(void);

int32_t oe_get_host_groups(size_t size, gid_t list[]);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_POSIX_UID_H */
