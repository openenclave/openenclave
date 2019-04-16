// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/stat.h>
#include <openenclave/internal/defs.h>
#include <sys/stat.h>

/*
**==============================================================================
**
** Verify that oe_stat and stat have same layout.
**
**==============================================================================
*/

OE_STATIC_ASSERT(sizeof(struct oe_stat) > 0);

OE_STATIC_ASSERT(sizeof(struct oe_stat) == sizeof(struct stat));
OE_CHECK_FIELD(struct oe_stat, struct stat, st_dev)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_ino)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_nlink)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_mode)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_uid)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_gid)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_rdev)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_size)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_blksize)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_blocks)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_atim)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_mtim)
OE_CHECK_FIELD(struct oe_stat, struct stat, st_ctim)
