// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_UTSNAME_H
#define _OE_SYS_UTSNAME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

OE_EXTERNC_BEGIN

#define __OE_UTSNAME oe_utsname
#include <openenclave/internal/syscall/sys/bits/utsname.h>
#undef __OE_UTSNAME

int oe_uname(struct oe_utsname* buf);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define __OE_UTSNAME utsname
#include <openenclave/internal/syscall/sys/bits/utsname.h>
#undef __OE_UTSNAME

OE_INLINE int uname(struct utsname* buf)
{
    return oe_uname((struct oe_utsname*)buf);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_UTSNAME_H */
