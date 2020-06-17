// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_HOST_H
#define _OE_SYSCALL_HOST_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

#if defined(_WIN32)
char* oe_win_path_to_posix(PCWSTR path);
#endif

OE_EXTERNC_END

#endif // _OE_SYSCALL_HOST_H
