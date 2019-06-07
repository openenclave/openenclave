// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* This header is a dependency for directly compiling MUSL memcpy
 * into oecore. It scopes down the determination of __BYTE_ORDER
 * relevant to memcpy avoiding GNUC/BSD specializations.
 */
#ifndef _OE_SYSCALL_ENDIAN_H
#define _OE_SYSCALL_ENDIAN_H

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __PDP_ENDIAN 3412

#if defined(__GNUC__) && defined(__BYTE_ORDER__)
#define __BYTE_ORDER __BYTE_ORDER__
#elif defined(__ARMEB__)
/* Defined for ARM by GCC when -mbig-endian is specified */
#define __BYTE_ORDER __BIG_ENDIAN
#else
/* For default ARM and x64 arch */
#define __BYTE_ORDER __LITTLE_ENDIAN
#endif

#endif /* _OE_SYSCALL_ENDIAN_H */
