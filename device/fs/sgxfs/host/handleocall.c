// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/fs.h>
#include "../common/sgxfsargs.h"
#include "sgx_tprotected_fs_u.h"

static void _handle_sgxfs_ocall(void* args_)
{
    oe_sgxfs_args_t* args = (oe_sgxfs_args_t*)args_;

    switch (args->op)
    {
        case oe_sgxfs_op_none:
        {
            break;
        }
        case oe_sgxfs_op_exclusive_file_open:
        {
            args->u.exclusive_file_open.retval =
                u_sgxprotectedfs_exclusive_file_open(
                    args->u.exclusive_file_open.filename,
                    args->u.exclusive_file_open.read_only,
                    &args->u.exclusive_file_open.file_size,
                    &args->u.exclusive_file_open.error_code);
            break;
        }
        case oe_sgxfs_op_check_if_file_exists:
        {
            args->u.check_if_file_exists.retval =
                u_sgxprotectedfs_check_if_file_exists(
                    args->u.check_if_file_exists.filename);
            break;
        }
        case oe_sgxfs_op_fread_node:
        {
            args->u.fread_node.retval = u_sgxprotectedfs_fread_node(
                args->u.fread_node.file,
                args->u.fread_node.node_number,
                args->u.fread_node.buffer,
                args->u.fread_node.node_size);
            break;
        }
        case oe_sgxfs_op_fwrite_node:
        {
            args->u.fwrite_node.retval = u_sgxprotectedfs_fwrite_node(
                args->u.fwrite_node.file,
                args->u.fwrite_node.node_number,
                args->u.fwrite_node.buffer,
                args->u.fwrite_node.node_size);
            break;
        }
        case oe_sgxfs_op_fclose:
        {
            args->u.fclose.retval =
                u_sgxprotectedfs_fclose(args->u.fclose.file);
            break;
        }
        case oe_sgxfs_op_fflush:
        {
            args->u.fflush.retval =
                u_sgxprotectedfs_fflush(args->u.fflush.file);
            break;
        }
        case oe_sgxfs_op_remove:
        {
            args->u.remove.retval =
                u_sgxprotectedfs_remove(args->u.remove.filename);
            break;
        }
        case oe_sgxfs_op_recovery_file_open:
        {
            args->u.recovery_file_open.retval =
                u_sgxprotectedfs_recovery_file_open(
                    args->u.recovery_file_open.filename);
            break;
        }
        case oe_sgxfs_op_fwrite_recovery_node:
        {
            args->u.fwrite_recovery_node.retval =
                u_sgxprotectedfs_fwrite_recovery_node(
                    args->u.fwrite_recovery_node.file,
                    args->u.fwrite_recovery_node.data,
                    args->u.fwrite_recovery_node.data_length);
            break;
        }
        case oe_sgxfs_op_do_file_recovery:
        {
            args->u.do_file_recovery.retval = u_sgxprotectedfs_do_file_recovery(
                args->u.do_file_recovery.filename,
                args->u.do_file_recovery.recovery_filename,
                args->u.do_file_recovery.node_size);
            break;
        }
    }
}

void (*oe_handle_sgxfs_ocall_callback)(void*);

void oe_fs_install_sgxfs(void)
{
    oe_handle_sgxfs_ocall_callback = _handle_sgxfs_ocall;
}
