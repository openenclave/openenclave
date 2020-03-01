// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <stdlib.h>
#include <string.h>

OE_EXTERNC_BEGIN

void oe_set_fs_register_base(const void* ptr);

void* oe_get_fs_register_base(void);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
