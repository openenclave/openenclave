// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/aesm.h>

static const uint32_t AESM_MAGIC = 0x4efaa2a3;

typedef UINT32 aesm_error_t;

typedef struct _iaesm_interface IAESMInterface;

/* Copied from MSR-SDK. This is the COM interface for calling into Intel's
 * AESM interface. This will eventually be replaced by a different interface
 * that Intel will be providing.
 */
typedef struct IAESMInterfaceVtbl
{
    BEGIN_INTERFACE

    HRESULT(STDMETHODCALLTYPE* QueryInterface)
    (IAESMInterface* This,
     /* [in] */ REFIID riid,
     /* [annotation][iid_is][out] */
     _COM_Outptr_ void** ppvObject);

    ULONG(STDMETHODCALLTYPE* AddRef)(IAESMInterface* This);

    ULONG(STDMETHODCALLTYPE* Release)(IAESMInterface* This);

    HRESULT(STDMETHODCALLTYPE* GetLicenseToken)
    (IAESMInterface* This,
     /* [size_is][ref][in] */ uint8_t* mrenclave,
     uint32_t mrenclave_size,
     /* [size_is][ref][in] */ uint8_t* public_key,
     uint32_t public_key_size,
     /* [size_is][ref][in] */ uint8_t* se_attributes,
     uint32_t se_attributes_size,
     /* [size_is][ref][out] */ uint8_t* lictoken,
     uint32_t lictoken_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* InitQuote)
    (IAESMInterface* This,
     /* [size_is][out] */ uint8_t* pTargetInfo,
     uint32_t targetInfoSize,
     /* [size_is][ref][out] */ uint8_t* pGID,
     uint32_t gidSize,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetQuote)
    (IAESMInterface* This,
     /* [size_is][ref][in] */ uint8_t* pReport,
     uint32_t reportSize,
     uint32_t type,
     /* [size_is][ref][in] */ uint8_t* pSPID,
     uint32_t spid_size,
     /* [size_is][unique][in] */ uint8_t* pNonce,
     uint32_t nonce_size,
     /* [size_is][unique][in] */ uint8_t* pSigRL,
     uint32_t sigRLSize,
     /* [size_is][unique][out][in] */ uint8_t* pQEReport,
     uint32_t qe_report_size,
     /* [size_is][ref][out][in] */ uint8_t* pQuote,
     /* [in] */ uint32_t bufSize,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* CreateSession)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* session_id,
     /* [size_is][ref][out] */ uint8_t* se_dh_msg1,
     uint32_t se_dh_msg1_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* ExchangeReport)
    (IAESMInterface* This,
     uint32_t session_id,
     /* [size_is][ref][in] */ uint8_t* se_dh_msg2,
     uint32_t se_dh_msg2_size,
     /* [size_is][ref][out] */ uint8_t* se_dh_msg3,
     uint32_t se_dh_msg3_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* CloseSession)
    (IAESMInterface* This,
     uint32_t session_id,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* InvokeService)
    (IAESMInterface* This,
     /* [size_is][ref][in] */ uint8_t* pse_message_req,
     uint32_t pse_message_req_size,
     /* [size_is][ref][out] */ uint8_t* pse_message_resp,
     uint32_t pse_message_resp_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* ReportAttestationStatus)
    (IAESMInterface* This,
     /* [size_is][ref][in] */ uint8_t* platform_info,
     uint32_t platform_info_size,
     uint32_t attestation_status,
     /* [size_is][ref][out] */ uint8_t* update_info,
     uint32_t update_info_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetPSCap)
    (IAESMInterface* This,
     /* [out] */ uint64_t* ps_cap,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* SgxRegister)
    (IAESMInterface* This,
     /* [size_is][ref][in] */ uint8_t* white_list_cert,
     uint32_t white_list_cert_size,
     uint32_t registration_data_type,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* ProxySettingAssist)
    (IAESMInterface* This,
     /* [size_is][unique][in] */ uint8_t* pProxyInfo,
     uint32_t proxy_size,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* QuerySgxStatus)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* sgx_status,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetWhitelistSize)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* pWhitelistSize,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetWhitelist)
    (IAESMInterface* This,
     /* [size_is][ref][out] */ uint8_t* pWhitelist,
     uint32_t bufSize,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetSecDomainId)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* sec_domain_id,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* SwitchSecDomain)
    (IAESMInterface* This,
     uint32_t sec_domain_id,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetEPIDProvisionStatus)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* epid_pr_status,
     /* [ref][out] */ aesm_error_t* pResult);

    HRESULT(STDMETHODCALLTYPE* GetPlatformServiceStatus)
    (IAESMInterface* This,
     /* [ref][out] */ uint32_t* pse_status,
     /* [ref][out] */ aesm_error_t* pResult);

    END_INTERFACE
} IAESMInterfaceVtbl;

struct _iaesm_interface
{
    CONST_VTBL struct IAESMInterfaceVtbl* lpVtbl;
};

static IAESMInterface* _create_instance()
{
    IAESMInterface* instance = NULL;
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
    if (!SUCCEEDED(
            CoCreateInstance(
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

static void _release_instance(IAESMInterface* instance)
{
    instance->lpVtbl->Release(instance);
    CoUninitialize();
}

struct _AESM
{
    uint32_t magic;
};

static int _aesm_valid(const AESM* aesm)
{
    return aesm != NULL && aesm->magic == AESM_MAGIC;
}

AESM* AESMConnect()
{
    AESM* aesm = NULL;
    IAESMInterface* instance = NULL;

    /* Obtain AESM COM object (as a test only) */
    if (!(instance = _create_instance()))
        goto done;

    /* Allocate and initialize AESM struct */
    {
        if (!(aesm = (AESM*)calloc(1, sizeof(AESM))))
            goto done;

        aesm->magic = AESM_MAGIC;
    }

done:

    if (instance)
        _release_instance(instance);

    return aesm;
}

void AESMDisconnect(AESM* aesm)
{
    if (_aesm_valid(aesm))
    {
        aesm->magic = 0xDDDDDDDD;
        free(aesm);
    }
}

oe_result_t AESMGetLaunchToken(
    AESM* aesm,
    uint8_t mrenclave[OE_SHA256_SIZE],
    uint8_t modulus[OE_KEY_SIZE],
    const sgx_attributes_t* attributes,
    sgx_launch_token_t* launchToken)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    IAESMInterface* instance = NULL;

    if (!_aesm_valid(aesm))
        goto done;

    /* Obtain AESM COM instance */
    if (!(instance = _create_instance()))
        goto done;

    /* Obtain a launch token */
    HRESULT hr = instance->lpVtbl->GetLicenseToken(
        instance,                 /* this */
        mrenclave,                /* mrenclave */
        OE_SHA256_SIZE,           /* mrenclave_size */
        modulus,                  /* public_key */
        OE_KEY_SIZE,              /* public_key_size */
        (PUINT8)attributes,       /* se_attributes */
        sizeof(sgx_attributes_t), /* se_attributes_size */
        (PUINT8)launchToken,      /* lictoken */
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

oe_result_t AESMInitQuote(
    AESM* aesm,
    sgx_target_info_t* targetInfo,
    sgx_epid_group_id_t* epidGroupID)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    IAESMInterface* instance = NULL;

    if (!_aesm_valid(aesm))
        goto done;

    /* Obtain AESM COM instance */
    if (!(instance = _create_instance()))
        goto done;

    // Get quote for a given report.
    HRESULT hr = instance->lpVtbl->InitQuote(
        instance,
        (uint8_t*)targetInfo,
        sizeof(sgx_target_info_t),
        (uint8_t*)epidGroupID,
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

oe_result_t AESMGetQuote(
    AESM* aesm,
    const sgx_report_t* report,
    sgx_quote_type_t quoteType,
    const sgx_spid_t* spid,
    const sgx_nonce_t* nonce,
    const uint8_t* signatureRevocationList,
    uint32_t signatureRevocationListSize,
    sgx_report_t* reportOut, /* ATTN: support this! */
    sgx_quote_t* quote,
    size_t quoteSize)
{
    oe_result_t result = OE_UNEXPECTED;
    aesm_error_t error;
    IAESMInterface* instance = NULL;

    if (quoteSize > UINT_MAX)
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
    HRESULT hr = instance->lpVtbl->GetQuote(
        instance,                          /* this */
        (uint8_t*)report,                  /* report */
        sizeof(sgx_report_t),              /* report_size */
        (uint32_t)quoteType,               /* type */
        (uint8_t*)spid,                    /* spid */
        sizeof(sgx_spid_t),                /* spid_size */
        (uint8_t*)nonce,                   /* nonce */
        sizeof(sgx_nonce_t),               /* nonce_size */
        (uint8_t*)signatureRevocationList, /* sigrl */
        signatureRevocationListSize,       /* sigrl_size */
        (uint8_t*)reportOut,               /* qe_report */
        sizeof(sgx_report_t),              /* qe_report_size */
        (uint8_t*)quote,                   /* quote */
        (uint32_t)quoteSize,               /* buffer_size */
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
