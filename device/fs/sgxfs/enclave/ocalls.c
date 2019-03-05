// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE

// clang-format off
#include <stdio.h>
#define FILE RENAME_FILE
#include "common.h"
#include "linux-sgx/sdk/protected_fs/sgx_tprotected_fs/sgx_tprotected_fs_t.h"
#include "sgx_error.h"
#undef FILE
// clang-format on

#include <pthread.h>
//#include <openenclave/internal/sgxfs.h>
#include "../common/sgxfsargs.h"
#include <openenclave/internal/hostbatch.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <string.h>
#include <stdio.h>

#define BATCH_SIZE 16 * 1024

typedef oe_sgxfs_args_t args_t;

OE_STATIC_ASSERT(sizeof(args_t) < BATCH_SIZE);

static bool _copy_path(char dest[SECURE_FILE_MAX_PATH], const char* src)
{
    return strlcpy(dest, src, SECURE_FILE_MAX_PATH) < SECURE_FILE_MAX_PATH;
}

static oe_host_batch_t* _batch;
static pthread_spinlock_t _lock;

static void _atexit_handler()
{
    pthread_spin_lock(&_lock);
    oe_host_batch_delete(_batch);
    _batch = NULL;
    pthread_spin_unlock(&_lock);
}

static oe_host_batch_t* _get_host_batch(void)
{
    if (_batch == NULL)
    {
        pthread_spin_lock(&_lock);

        if (_batch == NULL)
        {
            _batch = oe_host_batch_new(BATCH_SIZE);
            atexit(_atexit_handler);
        }

        pthread_spin_unlock(&_lock);
    }

    return _batch;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_exclusive_file_open(
    void** retval,
    const char* filename,
    uint8_t read_only,
    int64_t* file_size,
    int* error_code)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !filename || !file_size || !error_code || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_exclusive_file_open;

    if (!_copy_path(args->u.exclusive_file_open.filename, filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    args->u.exclusive_file_open.read_only = read_only;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.exclusive_file_open.retval;
    *file_size = args->u.exclusive_file_open.file_size;
    *error_code = args->u.exclusive_file_open.error_code;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL
u_sgxprotectedfs_check_if_file_exists(uint8_t* retval, const char* filename)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !filename || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_check_if_file_exists;

    if (!_copy_path(args->u.check_if_file_exists.filename, filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.check_if_file_exists.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fread_node(
    int* retval,
    void* file,
    uint64_t node_number,
    uint8_t* buffer,
    uint32_t node_size)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !file || !buffer || !node_size || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + node_size + 1)))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_fread_node;
    args->u.fread_node.file = file;
    args->u.fread_node.node_number = node_number;
    args->u.fread_node.buffer = args->buffer;
    args->u.fread_node.node_size = node_size;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    memcpy(buffer, args->buffer, node_size);
    *retval = args->u.fread_node.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_node(
    int* retval,
    void* file,
    uint64_t node_number,
    uint8_t* buffer,
    uint32_t node_size)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !file || !buffer || !node_size || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + node_size + 1)))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_fwrite_node;
    args->u.fwrite_node.file = file;
    args->u.fwrite_node.node_number = node_number;
    memcpy(args->buffer, buffer, node_size);
    args->u.fwrite_node.buffer = args->buffer;
    args->u.fwrite_node.node_size = node_size;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.fwrite_node.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fclose(int* retval, void* file)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !file || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_fclose;
    args->u.fclose.file = file;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.fclose.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fflush(uint8_t* retval, void* file)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !file || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_fflush;
    args->u.fflush.file = file;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = (uint8_t)args->u.fflush.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL
u_sgxprotectedfs_remove(int* retval, const char* filename)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !filename || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_remove;

    if (!_copy_path(args->u.remove.filename, filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.remove.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL
u_sgxprotectedfs_recovery_file_open(void** retval, const char* filename)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !filename || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_recovery_file_open;

    if (!_copy_path(args->u.recovery_file_open.filename, filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.recovery_file_open.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_fwrite_recovery_node(
    uint8_t* retval,
    void* file,
    uint8_t* data,
    uint32_t data_length)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !file || !data || !data_length || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t) + data_length + 1)))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    args->op = oe_sgxfs_op_fwrite_recovery_node;
    args->u.fwrite_recovery_node.file = file;
    memcpy(args->buffer, data, data_length);
    args->u.fwrite_recovery_node.data = args->buffer;
    args->u.fwrite_recovery_node.data_length = data_length;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.fwrite_recovery_node.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}

sgx_status_t SGX_CDECL u_sgxprotectedfs_do_file_recovery(
    int* retval,
    const char* filename,
    const char* recovery_filename,
    uint32_t node_size)
{
    sgx_status_t err = 0;
    args_t* args = NULL;
    oe_host_batch_t* batch = _get_host_batch();

    if (!retval || !filename || !recovery_filename || !node_size || !batch)
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!(args = oe_host_batch_calloc(batch, sizeof(args_t))))
    {
        err = SGX_ERROR_OUT_OF_MEMORY;
        goto done;
    }

    if (!_copy_path(args->u.do_file_recovery.filename, filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    if (!_copy_path(
            args->u.do_file_recovery.recovery_filename, recovery_filename))
    {
        err = SGX_ERROR_INVALID_PARAMETER;
        goto done;
    }

    args->op = oe_sgxfs_op_do_file_recovery;
    args->u.do_file_recovery.node_size = node_size;

    if (oe_ocall(OE_OCALL_SGXFS, (uint64_t)args, NULL) != OE_OK)
    {
        err = SGX_ERROR_UNEXPECTED;
        goto done;
    }

    *retval = args->u.do_file_recovery.retval;

done:

    if (args)
        oe_host_batch_free(batch);

    return err;
}
