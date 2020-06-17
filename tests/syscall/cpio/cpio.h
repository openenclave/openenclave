// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CPIO_H
#define _OE_CPIO_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** To create a CPIO archive from the current directory on Linux:
**
**     $ find . | cpio --create --format='newc' > ../archive
**
** To unpack an archive on Linux:
**
**     $ cpio -i < ../archive
**
**==============================================================================
*/

#define CPIO_PATH_MAX 256

#define OE_CPIO_FLAG_READ 0
#define OE_CPIO_FLAG_CREATE 1

#define OE_CPIO_MODE_IFMT 00170000
#define OE_CPIO_MODE_IFSOCK 0140000
#define OE_CPIO_MODE_IFLNK 0120000
#define OE_CPIO_MODE_IFREG 0100000
#define OE_CPIO_MODE_IFBLK 0060000
#define OE_CPIO_MODE_IFDIR 0040000
#define OE_CPIO_MODE_IFCHR 0020000
#define OE_CPIO_MODE_IFIFO 0010000
#define OE_CPIO_MODE_ISUID 0004000
#define OE_CPIO_MODE_ISGID 0002000
#define OE_CPIO_MODE_ISVTX 0001000

#define OE_CPIO_MODE_IRWXU 00700
#define OE_CPIO_MODE_IRUSR 00400
#define OE_CPIO_MODE_IWUSR 00200
#define OE_CPIO_MODE_IXUSR 00100

#define OE_CPIO_MODE_IRWXG 00070
#define OE_CPIO_MODE_IRGRP 00040
#define OE_CPIO_MODE_IWGRP 00020
#define OE_CPIO_MODE_IXGRP 00010

#define OE_CPIO_MODE_IRWXO 00007
#define OE_CPIO_MODE_IROTH 00004
#define OE_CPIO_MODE_IWOTH 00002
#define OE_CPIO_MODE_IXOTH 00001

typedef struct _oe_cpio oe_cpio_t;

typedef struct _oe_cpio_entry
{
    size_t size;
    uint32_t mode;
    char name[CPIO_PATH_MAX];
} oe_cpio_entry_t;

oe_cpio_t* oe_cpio_open(const char* path, uint32_t flags);

int oe_cpio_close(oe_cpio_t* cpio);

int oe_cpio_read_entry(oe_cpio_t* cpio, oe_cpio_entry_t* entry_out);

ssize_t oe_cpio_read_data(oe_cpio_t* cpio, void* data, size_t size);

int oe_cpio_write_entry(oe_cpio_t* cpio, const oe_cpio_entry_t* entry);

ssize_t oe_cpio_write_data(oe_cpio_t* cpio, const void* data, size_t size);

int oe_cpio_pack(const char* source, const char* target);

int oe_cpio_unpack(const char* source, const char* target);

OE_EXTERNC_END

#endif /* _OE_CPIO_H */
