// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_FDTABLE_H
#define _OE_SYSCALL_FDTABLE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/syscall/fd.h>

OE_EXTERNC_BEGIN

oe_fd_t* oe_fdtable_get(int fd, oe_fd_type_t type);

int oe_fdtable_assign(oe_fd_t* desc);

int oe_fdtable_reassign(int fd, oe_fd_t* new_desc, oe_fd_t** old_desc);

int oe_fdtable_release(int fd);

/**
 * Invokes **callback** for each fd of type **type** in the fdtable.
 *
 * The callback must not use any of the other fdtable functions.
 *
 * @param type The fd type of interest. Can be OE_FD_TYPE_ANY.
 * @param arg An argument passed to the callback.
 * @param callback The callback to be invoked.
 */
void oe_fdtable_foreach(
    oe_fd_type_t type,
    void* arg,
    void (*callback)(oe_fd_t* desc, void* arg));

OE_EXTERNC_END

#endif // _OE_SYSCALL_FDTABLE_H
