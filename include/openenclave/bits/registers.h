// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include <stdlib.h>
#include <string.h>

void oe_set_gs_register_base(const void* ptr);

void* oe_get_gs_register_base(void);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
