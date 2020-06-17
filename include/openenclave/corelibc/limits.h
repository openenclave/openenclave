// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* DISCLAIMER:
 * This header is published with no guarantees of stability and is not part
 * of the Open Enclave public API surface. It is only intended to be used
 * internally by the OE runtime. */

#ifndef _OE_LIMITS_H
#define _OE_LIMITS_H

#include <openenclave/bits/types.h>

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

#define OE_PATH_MAX 4096
#define OE_NGROUPS_MAX 32
#define OE_IOV_MAX 1024
#define OE_NAME_MAX 255

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define SCHAR_MIN OE_SCHAR_MIN
#define SCHAR_MAX OE_SCHAR_MAX
#define UCHAR_MAX OE_UCHAR_MAX
#define CHAR_MIN OE_CHAR_MIN
#define CHAR_MAX OE_CHAR_MAX
#define CHAR_BIT OE_CHAR_BIT
#define SHRT_MIN OE_SHRT_MIN
#define SHRT_MAX OE_SHRT_MAX
#define USHRT_MAX OE_USHRT_MAX
#define INT_MIN OE_INT_MIN
#define INT_MAX OE_INT_MAX
#define UINT_MAX OE_UINT_MAX
#define LONG_MAX OE_LONG_MAX
#define LONG_MIN OE_LONG_MIN
#define ULONG_MAX OE_ULONG_MAX
#define LLONG_MAX OE_LLONG_MAX
#define LLONG_MIN OE_LLONG_MIN
#define ULLONG_MAX OE_ULLONG_MAX
#define PATH_MAX OE_PATH_MAX
#define NGROUPS_MAX OE_NGROUPS_MAX
#define IOV_MAX OE_IOV_MAX
#define NAME_MAX OE_NAME_MAX

#endif /* defined(OE_NEED_STDC_NAMES) */

#endif /* _OE_LIMITS_H */
