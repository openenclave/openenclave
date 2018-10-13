/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <sgx.h>

/* Provide a dummy implementation of the APIs called by sgx_tprotectedfs.lib.
 * These will never be called, however, since on SGX they are called by
 * the implementation of sgx_fopen etc., which are mapped to different
 * implementations for OP-TEE.  The purpose is to allow code to import
 * sgx_fprotectedfs.edl and still work as if it were not imported.
 */

sgx_status_t close_session_ocall(uint32_t ms_sid, uint32_t ms_timeout)
{
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
}

sgx_status_t create_session_ocall(
    uint32_t* ms_sid,
    uint8_t* ms_dh_msg1,
    uint32_t ms_dh_msg1_size,
    uint32_t ms_timeout)
{
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
}

sgx_status_t invoke_service_ocall(
    uint8_t* ms_pse_message_req,
    uint32_t ms_pse_message_req_size,
    uint8_t* ms_pse_message_resp,
    uint32_t ms_pse_message_resp_size,
    uint32_t ms_timeout)
{
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
}

sgx_status_t exchange_report_ocall(
    uint32_t ms_sid,
    uint8_t* ms_dh_msg2,
    uint32_t ms_dh_msg2_size,
    uint8_t* ms_dh_msg3,
    uint32_t ms_dh_msg3_size,
    uint32_t ms_timeout)
{
    return SGX_ERROR_FEATURE_NOT_SUPPORTED;
}

void sgx_oc_cpuidex(int* ms_cpuinfo, int ms_leaf, int ms_subleaf)
{
}

int sgx_thread_wait_untrusted_event_ocall(const void* ms_self)
{
    return 0;
}

int sgx_thread_setwait_untrusted_events_ocall(
    const void* ms_waiter,
    const void* ms_self)
{
    return 0;
}

int sgx_thread_set_untrusted_event_ocall(const void* ms_waiter)
{
    return 0;
}

int sgx_thread_set_multiple_untrusted_events_ocall(const void** ms_waiters, size_t ms_total)
{
    return 0;
}

int32_t u_sgxprotectedfs_do_file_recovery(
    const char* ms_filename,
    const char* ms_recovery_filename,
    uint32_t ms_node_size)
{
    return 0;
}

uint8_t u_sgxprotectedfs_fwrite_recovery_node(
    void* ms_f,
    uint8_t* ms_data,
    uint32_t ms_data_length)
{
    return 0;
}

void* u_sgxprotectedfs_recovery_file_open(const char* ms_filename)
{
    return NULL;
}

int32_t u_sgxprotectedfs_remove(const char* ms_filename)
{
    return 0;
}

uint8_t u_sgxprotectedfs_fflush(void* ms_f)
{
    return 0;
}

int32_t u_sgxprotectedfs_fclose(void* ms_f)
{
    return 0;
}

int32_t u_sgxprotectedfs_fwrite_node(
    void* ms_f,
    uint64_t ms_node_number,
    uint8_t* ms_buffer,
    uint32_t ms_node_size)
{
    return 0;
}

int32_t u_sgxprotectedfs_fread_node(
    void* ms_f, 
    uint64_t ms_node_number, 
    uint8_t* ms_buffer, 
    uint32_t ms_node_size)
{
    return 0;
}

uint8_t u_sgxprotectedfs_check_if_file_exists(const char* ms_filename)
{
    return 0;
}

void* u_sgxprotectedfs_exclusive_file_open(
    const char* ms_filename, 
    uint8_t ms_read_only, 
    int64_t* ms_file_size, 
    int32_t* ms_error_code)
{
    return NULL;
}
