// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/setjmp.h>
#include <openenclave/internal/defs.h>
#include <setjmp.h>

OE_STATIC_ASSERT(sizeof(oe_jmp_buf) == sizeof(jmp_buf));
