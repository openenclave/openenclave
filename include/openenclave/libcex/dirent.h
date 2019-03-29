/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _LIBCEX_DIRENT_H
#define _LIBCEX_DIRENT_H

#if defined(_MSC_VER)
#define _NO_CRT_DIRENT_INLINE
#endif

#include <openenclave/bits/defs.h>
#include <openenclave/bits/io.h>
#include <openenclave/bits/types.h>
#include <openenclave/libcex/bits/common.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe-prefixed standard stream I/O functions (the "oe" namespace).
**
**==============================================================================
*/

typedef struct _OE_DIR OE_DIR;
struct oe_dirent;

OE_DIR* oe_opendir_d(uint64_t devid, const char* pathname);

struct oe_dirent* oe_readdir(OE_DIR* dir);

int oe_closedir(OE_DIR* dir);

/*
**==============================================================================
**
** Libc extensions:
**
**==============================================================================
*/

OE_INLINE OE_DIR* oe_opendir_nonsecure(const char* pathname)
{
    return oe_opendir_d(OE_DEVID_HOSTFS, pathname);
}

OE_INLINE OE_DIR* oe_opendir_secure_encrypted(const char* pathname)
{
    return oe_opendir_d(OE_DEVID_SGXFS, pathname);
}

OE_INLINE OE_DIR* oe_opendir_secure_hardware(const char* pathname)
{
    return oe_opendir_d(OE_DEVID_SHWFS, pathname);
}

OE_INLINE OE_DIR* oe_opendir_secure(const char* pathname)
{
    /* Default to the secure file system for this platform. */
#ifdef OE_USE_OPTEE
    return oe_opendir_secure_hardware(pathname);
#else
    return oe_opendir_secure_encrypted(pathname);
#endif
}

#ifndef OE_NO_POSIX_FILE_API
#define opendir oe_opendir_secure
#define readdir oe_readdir
#define closedir oe_closedir
#define DIR OE_DIR
#endif

OE_EXTERNC_END

#endif /* _LIBCEX_DIRENT_H */
