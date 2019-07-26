// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_UPCALLS_H
#define _OE_ENCLAVE_UPCALLS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/report.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

typedef oe_result_t (
    *oe_verify_report_upcall_t)(const void* report, size_t report_size);

typedef oe_result_t (*oe_get_public_key_by_policy_upcall_t)(
    uint32_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out,
    void* key_info,
    size_t key_info_size,
    size_t* key_info_size_out);

typedef oe_result_t (*oe_get_public_key_upcall_t)(
    const oe_asymmetric_key_params_t* key_params,
    const void* key_info,
    size_t key_info_size,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out);

oe_result_t oe_handle_verify_report_upcall(
    const void* report,
    size_t report_size);

oe_result_t oe_handle_get_public_key_upcall(
    const oe_asymmetric_key_params_t* key_params,
    const void* key_info,
    size_t key_info_size,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out);

oe_result_t oe_handle_get_public_key_by_policy_upcall(
    uint32_t seal_policy,
    const oe_asymmetric_key_params_t* key_params,
    void* key_buffer,
    size_t key_buffer_size,
    size_t* key_buffer_size_out,
    void* key_info,
    size_t key_info_size,
    size_t* key_info_size_out);

extern oe_verify_report_upcall_t oe_verify_report_upcall;

extern oe_get_public_key_by_policy_upcall_t oe_get_public_key_by_policy_upcall;

extern oe_get_public_key_upcall_t oe_get_public_key_upcall;

void oe_set_verify_report_upcall(oe_verify_report_upcall_t upcall);

void oe_set_get_public_key_by_policy_upcall(
    oe_get_public_key_by_policy_upcall_t upcall);

void oe_set_get_public_key_upcall(oe_get_public_key_upcall_t upcall);

#endif /* _OE_ENCLAVE_UPCALLS_H */
