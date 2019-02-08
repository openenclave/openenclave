// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ERRNO_H
#define _OE_ERRNO_H

/*
 * Use MUSL generic arch errno definitions directly without the OE_ prefix.
 * These should be directly compatible across arch except for MIPS & PowerPC.
 */
#include "../../../3rdparty/musl/musl/arch/generic/bits/errno.h"

extern int* __oe_errno_location(void);

#define oe_errno *__oe_errno_location()

#if defined(OE_NEED_STDC_NAMES)

#define errno oe_errno

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_ERRNO_H */
