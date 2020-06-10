// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

#ifndef _OE_WCHAR_H
#define _OE_WCHAR_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

size_t oe_wcslen(const wchar_t* s);

OE_EXTERNC_END

#endif
