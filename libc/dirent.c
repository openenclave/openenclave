// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <dirent.h>
#include <openenclave/corelibc/dirent.h>
#include <openenclave/internal/defs.h>

/*
**==============================================================================
**
** Verify that oe_dirent and dirent have same layout.
**
**==============================================================================
*/

OE_STATIC_ASSERT(sizeof(struct oe_dirent) == sizeof(struct dirent));
OE_CHECK_FIELD(struct oe_dirent, struct dirent, d_ino)
OE_CHECK_FIELD(struct oe_dirent, struct dirent, d_off)
OE_CHECK_FIELD(struct oe_dirent, struct dirent, d_reclen)
OE_CHECK_FIELD(struct oe_dirent, struct dirent, d_type)
OE_CHECK_FIELD(struct oe_dirent, struct dirent, d_name)
