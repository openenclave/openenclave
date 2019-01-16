// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/aesm.h>

static const uint32_t AESM_MAGIC = 0x4efaa2a3;

typedef UINT32 aesm_error_t;

typedef struct _aesm_interface aesm_interface_t;

/* Copied from MSR-SDK. This is the COM interface for calling into Intel's
 * AESM interface. This will eventually be replaced by a different interface
 * that Intel will be providing.
 */
typedef struct aesm_interface_vtbl
{
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* query_interface)
    (aesm_interface_t* this,
     /* [in] */ REFIID riid,
     /* [annotation][iid_is][out] */
     _COM_Outptr_ void** object);

    ULONG(STDMETHODCALLTYPE* add_ref)(aesm_interface_t* this);

    ULONG(STDMETHODCALLTYPE* release)(aesm_interface_t* this);

    HRESULT(STDMETHODCALLTYPE* get_license_token)
    (aesm_interface_t* this,
     /* [size_is][ref][in] */ uint8_t* mrenclave,
     uint32_t mrenclave_size,
     /* [size_is][ref][in] */ uint8_t* public_key,
     uint32_t public_key_size,
     /* [size_is][ref][in] */ uint8_t* se_attributes,
     uint32_t se_attributes_size,
     /* [size_is][ref][out] */ uint8_t* lictoken,
     uint32_t lictoken_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* init_quote)
    (aesm_interface_t* this,
     /* [size_is][out] */ uint8_t* target_info,
     uint32_t target_info_size,
     /* [size_is][ref][out] */ uint8_t* gid,
     uint32_t gid_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_quote)
    (aesm_interface_t* this,
     /* [size_is][ref][in] */ uint8_t* report,
     uint32_t report_size,
     uint32_t type,
     /* [size_is][ref][in] */ uint8_t* spid,
     uint32_t spid_size,
     /* [size_is][unique][in] */ uint8_t* nonce,
     uint32_t nonce_size,
     /* [size_is][unique][in] */ uint8_t* sig_rl,
     uint32_t sig_rl_size,
     /* [size_is][unique][out][in] */ uint8_t* qe_report,
     uint32_t qe_report_size,
     /* [size_is][ref][out][in] */ uint8_t* quote,
     /* [in] */ uint32_t buf_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* create_session)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* session_id,
     /* [size_is][ref][out] */ uint8_t* se_dh_msg1,
     uint32_t se_dh_msg1_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* exchange_report)
    (aesm_interface_t* this,
     uint32_t session_id,
     /* [size_is][ref][in] */ uint8_t* se_dh_msg2,
     uint32_t se_dh_msg2_size,
     /* [size_is][ref][out] */ uint8_t* se_dh_msg3,
     uint32_t se_dh_msg3_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* close_session)
    (aesm_interface_t* this,
     uint32_t session_id,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* invoke_service)
    (aesm_interface_t* this,
     /* [size_is][ref][in] */ uint8_t* pse_message_req,
     uint32_t pse_message_req_size,
     /* [size_is][ref][out] */ uint8_t* pse_message_resp,
     uint32_t pse_message_resp_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* report_attestation_status)
    (aesm_interface_t* this,
     /* [size_is][ref][in] */ uint8_t* platform_info,
     uint32_t platform_info_size,
     uint32_t attestation_status,
     /* [size_is][ref][out] */ uint8_t* update_info,
     uint32_t update_info_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_ps_cap)
    (aesm_interface_t* this,
     /* [out] */ uint64_t* ps_cap,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* sgx_register)
    (aesm_interface_t* this,
     /* [size_is][ref][in] */ uint8_t* white_list_cert,
     uint32_t white_list_cert_size,
     uint32_t registration_data_type,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* proxy_setting_assist)
    (aesm_interface_t* this,
     /* [size_is][unique][in] */ uint8_t* proxy_info,
     uint32_t proxy_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* query_sgx_status)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* sgx_status,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_whitelist_size)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* white_list_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_white_list)
    (aesm_interface_t* this,
     /* [size_is][ref][out] */ uint8_t* white_list,
     uint32_t buf_size,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_sec_domain_id)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* sec_domain_id,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* switch_sec_domain)
    (aesm_interface_t* this,
     uint32_t sec_domain_id,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_epid_provision_status)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* epid_pr_status,
     /* [ref][out] */ aesm_error_t* result);

    HRESULT(STDMETHODCALLTYPE* get_platform_service_status)
    (aesm_interface_t* this,
     /* [ref][out] */ uint32_t* pse_status,
     /* [ref][out] */ aesm_error_t* result);

    END_INTERFACE
} aesm_interface_vtbl;

struct _aesm_interface
{
    CONST_VTBL struct aesm_interface_vtbl* vtbl;
};

static aesm_interface_t* _create_instance()
{
    aesm_interface_t* instance = NULL;
    static const CLSID CLSID_AESMInterface = {
        0x82367CAB,
        0xF2B9,
        0x461A,
        {0xB6, 0xC6, 0x88, 0x9D, 0x13, 0xEF, 0xC6, 0xCA}};
    static const IID IID_IAESMInterface = {
        0x50AFD900,
        0xF309,
        0x4557,
        {0x8F, 0xCB, 0x10, 0xCF, 0xAB, 0x80, 0x2C, 0xDD}};

    /* Initialize COM library */
    {
        HRESULT hr = CoInitializeEx(
            NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

        /* If COM initialization failed */
        if (hr != S_OK && hr != S_FALSE)
            goto done;
    }

    /* Create AESM interface object */
    if (!SUCCEEDED(CoCreateInstance(
            &CLSID_AESMInterface,
            NULL,
            CLSCTX_ALL,
            &IID_IAESMInterface,
            &instance)))
    {
        CoUninitialize();
        goto done;
    }

done:

    return instance;
}

static void _release_instance(aesm_interface_t* instance)
{
    instance->vtbl->release(instance);
    CoUninitialize();
}

struct _aesm
{
    uint32_t magic;
};

static int _aesm_valid(const aesm_t* aesm)
{
    return aesm != NULL && aesm->magic == AESM_MAGIC;
}

aesm_t* aesm_connect()
{
    aesm_t* aesm = NULL;
    aesm_interface_t* instance = NULL;

    /* Obtain AESM COM object (as a test only) */
    if (!(instance = _create_instance()))
        goto done;

    /* Allocate and initialize AESM struct */
    {
        if (!(aesm = (aesm_t*)calloc(1, sizeof(aesm_t))))
            goto done;

        aesm->magic = AESM_MAGIC;
    }

done:

    if (instance)
        _release_instance(instance);

    return aesm;
}

void aesm_disconnect(aesm_t* aesm)
{
    if (_aesm_valid(aesm))
    {
        aesm->magic = 0xDDDDDDDD;
        free(aesm);
    }
}

oe_result_t aesm_get_launch_token(
    aesm_t* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const sgx_attributes_t* attributes,
    sgx_launch_token_t* launch_token)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    aesm_interface_t* instance = NULL;

    if (!_aesm_valid(aesm))
        goto done;

    /* Obtain AESM COM instance */
    if (!(instance = _create_instance()))
        goto done;

    /* Obtain a launch token */
    HRESULT hr = instance->vtbl->get_license_token(
        instance,                 /* this */
        mrenclave,                /* mrenclave */
        OE_SHA256_SIZE,           /* mrenclave_size */
        modulus,                  /* public_key */
        OE_KEY_SIZE,              /* public_key_size */
        (PUINT8)attributes,       /* se_attributes */
        sizeof(sgx_attributes_t), /* se_attributes_size */
        (PUINT8)launch_token,     /* lictoken */
        /* MSR-SDK passes sizeof(sgx_einittoken_t) */
        sizeof(sgx_einittoken_t), /* lictoken_size */
        &error);                  /* result */

    if (!SUCCEEDED(hr) || error != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    if (instance)
        _release_instance(instance);

    return result;
}

oe_result_t aesm_init_quote(
    aesm_t* aesm,
    sgx_target_info_t* target_info,
    sgx_epid_group_id_t* epid_group_id)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    aesm_interface_t* instance = NULL;

    if (!_aesm_valid(aesm))
        goto done;

    /* Obtain AESM COM instance */
    if (!(instance = _create_instance()))
        goto done;

    // Get quote for a given report.
    HRESULT hr = instance->vtbl->init_quote(
        instance,
        (uint8_t*)target_info,
        sizeof(sgx_target_info_t),
        (uint8_t*)epid_group_id,
        sizeof(sgx_epid_group_id_t),
        &error);

    if (!SUCCEEDED(hr) || error != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    if (instance)
        _release_instance(instance);

    return result;
}

oe_result_t aesm_get_quote(
    aesm_t* aesm,
    const sgx_report_t* report,
    sgx_quote_type_t quote_type,
    const sgx_spid_t* spid,
    const sgx_nonce_t* nonce,
    const uint8_t* signature_revocation_list,
    uint32_t signature_revocation_list_size,
    sgx_report_t* report_out, /* ATTN: support this! */
    sgx_quote_t* quote,
    size_t quote_size)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    aesm_interface_t* instance = NULL;

    if (quote_size > UINT_MAX)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!_aesm_valid(aesm))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Obtain AESM COM instance */
    if (!(instance = _create_instance()))
        goto done;

    // Get quote for a given report.
    HRESULT hr = instance->vtbl->get_quote(
        instance,                            /* this */
        (uint8_t*)report,                    /* report */
        sizeof(sgx_report_t),                /* report_size */
        (uint32_t)quote_type,                /* type */
        (uint8_t*)spid,                      /* spid */
        sizeof(sgx_spid_t),                  /* spid_size */
        (uint8_t*)nonce,                     /* nonce */
        sizeof(sgx_nonce_t),                 /* nonce_size */
        (uint8_t*)signature_revocation_list, /* sig_rl */
        signature_revocation_list_size,      /* sigrl_size */
        (uint8_t*)report_out,                /* qe_report */
        sizeof(sgx_report_t),                /* qe_report_size */
        (uint8_t*)quote,                     /* quote */
        (uint32_t)quote_size,                /* buffer_size */
        &error);

    if (!SUCCEEDED(hr) || error != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    if (instance)
        _release_instance(instance);

    return result;
}
