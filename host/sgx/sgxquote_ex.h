// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SGXQUOTE_EX_H
#define _OE_SGXQUOTE_EX_H

#if defined(OE_LINK_SGX_DCAP_QL)

#include <openenclave/bits/evidence.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

// Declarations for quote_ex integration
// Note: the quote_ex library entry points are based on declarations in
// https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_uae_quote_ex.h

enum _status_t;
typedef enum _status_t sgx_status_t;

struct _quote_t;
typedef struct _quote_t sgx_quote_t;

struct _att_key_id_t;
typedef struct _att_key_id_t sgx_att_key_id_t;

struct _sgx_ql_att_key_id_t;
typedef struct _sgx_ql_att_key_id_t sgx_ql_att_key_id_t;

struct _sgx_att_key_id_ext_t;
typedef struct _sgx_att_key_id_ext_t sgx_att_key_id_ext_t;

struct _qe_report_info_t;
typedef struct _qe_report_info_t sgx_qe_report_info_t;

struct _target_info_t;
typedef struct _target_info_t sgx_target_info_t;

struct _report_t;
typedef struct _report_t sgx_report_t;

typedef sgx_status_t (*sgx_select_att_key_id_t)(
    const uint8_t* p_att_key_id_list,
    uint32_t att_key_id_list_size,
    sgx_att_key_id_t* p_selected_key_id);

typedef sgx_status_t (*sgx_init_quote_ex_t)(
    const sgx_att_key_id_t* p_att_key_id,
    sgx_target_info_t* p_qe_target_info,
    size_t* p_pub_key_id_size,
    uint8_t* p_pub_key_id);

typedef sgx_status_t (*sgx_get_quote_size_ex_t)(
    const sgx_att_key_id_t* p_att_key_id,
    uint32_t* p_quote_size);

typedef sgx_status_t (*sgx_get_quote_ex_t)(
    const sgx_report_t* p_app_report,
    const sgx_att_key_id_t* p_att_key_id,
    sgx_qe_report_info_t* p_qe_report_info,
    uint8_t* p_quote,
    uint32_t quote_size);

typedef sgx_status_t (*sgx_get_supported_att_key_id_num_t)(
    uint32_t* p_att_key_id_num);

typedef sgx_status_t (*sgx_get_supported_att_key_ids_t)(
    sgx_att_key_id_ext_t* p_att_key_id_list,
    uint32_t att_key_id_num);

typedef struct _oe_sgx_quote_ex_library_t
{
    void* handle;
    oe_result_t load_result;

    // quote_ex shared library entry points
    sgx_select_att_key_id_t sgx_select_att_key_id;
    sgx_init_quote_ex_t sgx_init_quote_ex;
    sgx_get_quote_size_ex_t sgx_get_quote_size_ex;
    sgx_get_quote_ex_t sgx_get_quote_ex;
    sgx_get_supported_att_key_id_num_t sgx_get_supported_att_key_id_num;
    sgx_get_supported_att_key_ids_t sgx_get_supported_att_key_ids;

    // Map between OE uuid and SGX key ID
    size_t key_id_count;
    size_t mapped_key_id_count;
    bool* mapped;
    oe_uuid_t* uuid;
    sgx_att_key_id_ext_t* sgx_key_id;
} oe_sgx_quote_ex_library_t;

oe_result_t oe_initialize_quote_ex_library(void);

void oe_load_quote_ex_library(oe_sgx_quote_ex_library_t* library);

#define SGX_SELECT_ATT_KEY_ID_NAME "sgx_select_att_key_id"
#define SGX_INIT_QUOTE_EX_NAME "sgx_init_quote_ex"
#define SGX_GET_QUOTE_SIZE_NAME "sgx_get_quote_size_ex"
#define SGX_GET_QUOTE_EX_NAME "sgx_get_quote_ex"
#define SGX_GET_SUPPORTED_ATT_KEY_ID_NUM_NAME "sgx_get_supported_att_key_id_num"
#define SGX_GET_SUPPORTED_ATT_KEY_IDS_NAME "sgx_get_supported_att_key_ids"

OE_EXTERNC_END

#endif // OE_LINK_SGX_DCAP_QL

#endif // _OE_SGXQUOTE_EX_H
