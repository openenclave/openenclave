/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <stdlib.h>
#include <string.h>
#include <openenclave/enclave.h>
#include "enclavelibc.h"
#include <sgx_trts.h>
#include <sgx_utils.h>
#include "../oeresult.h"
#include <RiotStatus.h>
#include <RiotEcc.h>
#include <RiotCrypt.h>
#include <RiotDerEnc.h>
#include <RiotX509Bldr.h>

/* DER buffer used for private / public key export */
#define DER_MAX_SIZE 130

oe_result_t oe_get_seal_key_by_policy_v2(
    _In_ oe_seal_policy_t seal_policy,
    _Outptr_ uint8_t** key_buffer,
    _Out_ size_t* key_buffer_size,
    _Outptr_opt_ uint8_t** key_info,
    _Out_ size_t* key_info_size)
{
    sgx_report_t sgxReport = { 0 };
    sgx_status_t sgxStatus = sgx_create_report(NULL, NULL, &sgxReport);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }

    sgx_key_request_t key_request = { 0 };
    key_request.key_name = SGX_KEYSELECT_SEAL;
    switch (seal_policy) {
    case OE_SEAL_POLICY_UNIQUE:
        key_request.key_policy = SGX_KEYPOLICY_MRENCLAVE;
        break;
    case OE_SEAL_POLICY_PRODUCT:
        key_request.key_policy = SGX_KEYPOLICY_MRSIGNER;
        break;
    default:
        return OE_INVALID_PARAMETER;
    }
    key_request.isv_svn = sgxReport.body.isv_svn;
    key_request.cpu_svn = sgxReport.body.cpu_svn;
    key_request.attribute_mask = sgxReport.body.attributes;
    oe_result_t oeResult = oe_random(&key_request.key_id, sizeof(key_request.key_id));
    if (oeResult != OE_OK) {
        return oeResult;
    }

    uint8_t* info = NULL;
    if (key_info != NULL) {
        info = (uint8_t*)oe_malloc(sizeof(key_request));
        if (info == NULL) {
            return OE_OUT_OF_MEMORY;
        }
        memcpy(info, &key_request, sizeof(key_request));
    }

    oeResult = oe_get_seal_key_v2((uint8_t*)&key_request, sizeof(key_request), key_buffer, key_buffer_size);
    if (oeResult != OE_OK) {
        oe_free_key(NULL, info);
        return oeResult;
    }

    *key_info_size = sizeof(key_request);
    if (key_info != NULL) {
        *key_info = info;
    } else {
        oe_free_key(NULL, info);
    }
    return OE_OK;
}

/* Get a symmetric encryption key from the enclave platform using existing key information. */
oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    if (key_info_size < sizeof(sgx_key_request_t)) {
        key_info_size = sizeof(sgx_key_request_t);
        return OE_INVALID_PARAMETER;
    }
    sgx_key_request_t* key_request = (sgx_key_request_t*)key_info;

    uint8_t* key = (uint8_t*)oe_malloc(sizeof(sgx_key_128bit_t));
    if (key == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    sgx_status_t sgxStatus = sgx_get_key(key_request, (sgx_key_128bit_t*)key);
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    if (oeResult != OE_OK) {
        oe_free(key);
        return oeResult;
    }

    *key_buffer = key;
    *key_buffer_size = sizeof(sgx_key_128bit_t);
    return OE_OK;
}

oe_result_t oe_export_pem(
    _In_ DERBuilderContext* der_builder,
    _In_ uint32_t pem_type,
    _Outptr_ char** pem_buffer,
    _Out_ size_t* pem_buffer_size)
{
    uint32_t length = 0;
    DERtoPEM(der_builder, pem_type, NULL, &length);
    if (length == 0) {
        return OE_FAILURE;
    }

    char* pem = NULL;
    pem = (char*)oe_malloc(length);
    if (pem == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    if (DERtoPEM(der_builder, pem_type, pem, &length) < 0) {
        oe_free(pem);
        return OE_FAILURE;
    }

    *pem_buffer = pem;
    *pem_buffer_size = length;
    return OE_OK;
}

/* Derive a key pair based of a policy controlled secret */
oe_result_t oe_derive_key_pair(
    _In_ const void *secret,
    _In_ size_t secret_size,
    _Outptr_opt_ uint8_t** public_key,
    _Out_ size_t* public_key_size,
    _Outptr_opt_ uint8_t** private_key,
    _Out_ size_t* private_key_size)
{
    /* Require at least one out key. */
    if (public_key == NULL && private_key == NULL) {
        return OE_INVALID_PARAMETER;
    }

    sgx_report_t sgxReport = { 0 };
    sgx_status_t sgxStatus = sgx_create_report(NULL, NULL, &sgxReport);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }

    /* Derive an P256 ECC key using the enclave measurement. */
    RIOT_ECC_PUBLIC local_public_key;
    RIOT_ECC_PRIVATE local_private_key;
    RIOT_STATUS riotStatus = RiotCrypt_DeriveEccKey(&local_public_key,
                                                    &local_private_key,
                                                    secret,
                                                    secret_size,
                                                    sgxReport.body.mr_enclave.m,
                                                    sizeof(sgxReport.body.mr_enclave));
    if (riotStatus != RIOT_SUCCESS) {
        return OE_FAILURE;
    }

    oe_result_t oeResult;
    DERBuilderContext der_builder;
    uint8_t derBuffer[DER_MAX_SIZE] = { 0 };
    if (public_key != NULL) {
        DERInitContext(&der_builder, derBuffer, DER_MAX_SIZE);
        X509GetDEREccPub(&der_builder, local_public_key);
        oeResult = oe_export_pem(&der_builder, R_PUBLICKEY_TYPE, (char**)public_key, public_key_size);
        if (oeResult != OE_OK) {
            return oeResult;
        }
    }

    if (private_key != NULL) {
        DERInitContext(&der_builder, derBuffer, DER_MAX_SIZE);
        X509GetDEREcc(&der_builder, local_public_key, local_private_key);
        oeResult = oe_export_pem(&der_builder, R_ECC_PRIVATEKEY_TYPE, (char**)private_key, private_key_size);
        if (oeResult != OE_OK) {
            if (public_key != NULL && *public_key != NULL) {
                oe_free(public_key);
            }
            return oeResult;
        }
    }

    return OE_OK;
}

oe_result_t oe_get_key_pair_by_policy(
    _In_ oe_seal_policy_t seal_policy,
    _Outptr_opt_ uint8_t** public_key,
    _Out_ size_t* public_key_size,
    _Outptr_opt_ uint8_t** private_key,
    _Out_ size_t* private_key_size,
    _Outptr_opt_ uint8_t** key_info,
    _Out_ size_t* key_info_size)
{
    /* Obtain a seal key based on policy to use as the derivation secret. */
    uint8_t* secret = NULL;
    size_t secret_size = 0;
    uint8_t* local_key_info = NULL;
    size_t local_key_info_size = 0;
    oe_result_t oeResult = oe_get_seal_key_by_policy_v2(seal_policy,
                                                        &secret,
                                                        &secret_size,
                                                        &local_key_info,
                                                        &local_key_info_size);
    if (oeResult != OE_OK) {
        goto cleanup;
    }

    oeResult = oe_derive_key_pair(secret,
                                  secret_size,
                                  public_key,
                                  public_key_size,
                                  private_key,
                                  private_key_size);
    if (oeResult != OE_OK) {
        goto cleanup;
    }

    /* Success. Copy outptr */
    oeResult = OE_OK;
    if (key_info != NULL) {
        *key_info = local_key_info;
        *key_info_size = local_key_info_size;
        local_key_info = NULL;
    }

cleanup:

    oe_free(local_key_info);
    oe_free(secret);

    return oeResult;
}

oe_result_t oe_get_public_key_by_policy(
    oe_seal_policy_t seal_policy,
    uint8_t** key_buffer,
    size_t* key_buffer_size,
    uint8_t** key_info,
    size_t* key_info_size)
{
    return  oe_get_key_pair_by_policy(seal_policy,
                                      key_buffer,
                                      key_buffer_size,
                                      NULL,
                                      NULL,
                                      key_info,
                                      key_info_size);
}

 oe_result_t oe_get_public_key(
     const uint8_t* key_info,
     size_t key_info_size,
     uint8_t** key_buffer,
     size_t* key_buffer_size)
{
    uint8_t* seal_secret = NULL;
    size_t seal_secret_size;
    oe_result_t oeResult = oe_get_seal_key_v2(key_info,
                                              key_info_size,
                                              &seal_secret,
                                              &seal_secret_size);
    if (oeResult != OE_OK) {
        return oeResult;
    }

    oeResult = oe_derive_key_pair(seal_secret,
                                  seal_secret_size,
                                  key_buffer,
                                  key_buffer_size,
                                  NULL,
                                  NULL);

    oe_free(seal_secret);
    return oeResult;
}

 oe_result_t oe_get_private_key_by_policy(
     oe_seal_policy_t seal_policy,
     uint8_t** key_buffer,
     size_t* key_buffer_size,
     uint8_t** key_info,
     size_t* key_info_size)
{
    return oe_get_key_pair_by_policy(seal_policy,
                                     NULL,
                                     NULL,
                                     key_buffer,
                                     key_buffer_size,
                                     key_info,
                                     key_info_size);
}

 oe_result_t oe_get_private_key(
     const uint8_t* key_info,
     size_t key_info_size,
     uint8_t** key_buffer,
     size_t* key_buffer_size)
{
    uint8_t* secret = NULL;
    size_t secret_size;
    oe_result_t oeResult = oe_get_seal_key_v2(key_info,
                                              key_info_size,
                                              &secret,
                                              &secret_size);
    if (oeResult != OE_OK) {
        return oeResult;
    }

    oeResult = oe_derive_key_pair(secret,
                                  secret_size,
                                  NULL,
                                  NULL,
                                  key_buffer,
                                  key_buffer_size);
    oe_free(secret);
    return oeResult;
}