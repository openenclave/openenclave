// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BACKTRACE_H
#define _OE_BACKTRACE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/**
 * This function behaves like the GNU **backtrace** function. See the 
 * **backtrace** manpage for more information.
 */
int oe_backtrace(void** buffer, int size);

OE_EXTERNC_END

#endif /* _OE_BACKTRACE_H */
