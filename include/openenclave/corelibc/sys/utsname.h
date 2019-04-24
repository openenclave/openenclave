// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_UTSNAME_H
#define _OE_SYS_UTSNAME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

#define __OE_STRUCT_UTSNAME oe_utsname
#include <openenclave/corelibc/sys/bits/utsname.h>
#undef __OE_STRUCT_UTSNAME

int oe_uname(struct oe_utsname* buf);

#if defined(OE_NEED_STDC_NAMES)

#define __OE_STRUCT_UTSNAME utsname
#include <openenclave/corelibc/sys/bits/utsname.h>
#undef __OE_STRUCT_UTSNAME

int uname(struct oe_utsname* buf);

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_UTSNAME_H */
