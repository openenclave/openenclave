// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_COMMANDS_H
#define _OE_COMMANDS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/fs.h>
#include "../common/strarr.h"

OE_EXTERNC_BEGIN

int oe_lsr(const char* root, oe_strarr_t* paths);

int oe_cmp(const char* path1, const char* path2);

OE_EXTERNC_END

#endif /* _OE_COMMANDS_H */
