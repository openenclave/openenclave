// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ASM_H
#define _OE_ASM_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <stdlib.h>
#include <string.h>

void OE_SetGSRegisterBase(const void* ptr);

void* OE_GetGSRegisterBase(void);

OE_EXTERNC_END

#endif /* _OE_ASM_H */
