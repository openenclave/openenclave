// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_HOST_H
#define _OE_SYSCALL_HOST_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

char* oe_win_path_to_posix(const char* path);

OE_EXTERNC_END

#endif // _OE_SYSCALL_HOST_H
