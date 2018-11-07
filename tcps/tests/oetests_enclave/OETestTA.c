/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

/* Allow deprecated APIs in this file, since we need to test them. */
#define OE_ALLOW_DEPRECATED_APIS

#include "oetests_t.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/random.h>
#include "TcpsCallbacks_t.h"
#include <stdlib.h>
#include <string.h>

oe_result_t ecall_TestOEIsWithinEnclave(void* outside, int size)
{
    /* Generated code always calls is_within_enclave on secure memory,
     * when making OCALLs.
     */
    char inside[80];
    int result = oe_is_within_enclave(inside, size);
    Tcps_ReturnErrorIfTrue(result == 0, OE_FAILURE);

    int insideHandle = GetSecureCallbackId(0, NULL, NULL, NULL);
    Tcps_ReturnErrorIfTrue(insideHandle <= 0, OE_FAILURE);

    /* Callback handles aren't the same as an address in the enclave. */
    result = oe_is_within_enclave((void*)insideHandle, 4);
    FreeSecureCallbackContext(insideHandle);
    Tcps_ReturnErrorIfTrue(result != 0, OE_FAILURE);

#if !(defined(USE_OPTEE) && defined(SIMULATE_TEE))
    /* This test currently doesn't work in the OP-TEE simulator, but it's
     * a case never hit normally by generated code, and it should work
     * on actual OP-TEE.
     */
    result = oe_is_within_enclave(outside, size);
    Tcps_ReturnErrorIfTrue(result != 0, OE_FAILURE);
#endif

    return OE_OK;
}

oe_result_t ecall_TestOEIsOutsideEnclave(void* outside, int size)
{
    /* Generated code always calls is_outside_enclave on normal memory,
     * when handling ECALLs.
     */
    int result = oe_is_outside_enclave(outside, size);
    Tcps_ReturnErrorIfTrue(result == 0, OE_FAILURE);

    /* Callback handles aren't the same as an address in the enclave. */
    int insideHandle = GetSecureCallbackId(0, NULL, NULL, NULL);
    Tcps_ReturnErrorIfTrue(insideHandle <= 0, OE_FAILURE);

    result = oe_is_outside_enclave((void*)insideHandle, 4);
    FreeSecureCallbackContext(insideHandle);
    Tcps_ReturnErrorIfTrue(result == 0, OE_FAILURE);

#if !(defined(USE_OPTEE) && defined(SIMULATE_TEE))
    /* This test currently doesn't work in the OP-TEE simulator, but it's
    * a case never hit normally by generated code, and it should work
    * on actual OP-TEE.
    */
    char inside[80];
    result = oe_is_outside_enclave(inside, size);
    Tcps_ReturnErrorIfTrue(result != 0, OE_FAILURE);
#endif

    return OE_OK;
}

oe_result_t ecall_TestOERandom()
{
    oe_result_t result;
    int i;
    int delta[255] = { 0 };
    uint8_t newValue;
    uint8_t oldValue = 0;
    int diff;
    int count = 0;

    // Generate 100 random 1-byte numbers.
    for (i = 0; i < 100; i++) {
        result = oe_random(&newValue, sizeof(newValue));
        if (result != OE_OK) {
            return result;
        }
        if (i > 0) {
            diff = abs(newValue - oldValue);
            delta[diff]++;
        }
        oldValue = newValue;
    }

    // Count how many deltas we saw.
    for (i = 0; i < 255; i++) {
        if (delta[i] > 0) {
            count++;
        }
    }

    return (count > 2) ? OE_OK : OE_FAILURE;
}

oe_result_t ecall_TestOEGetReportV1(uint32_t flags)
{
    uint8_t report_buffer[1024];
    size_t report_buffer_size = sizeof(report_buffer);
    uint8_t report_data[OE_REPORT_DATA_SIZE] = { 0 };
    size_t report_data_size = OE_REPORT_DATA_SIZE;

    oe_result_t oeResult = oe_get_report_v1(flags,
                                            report_data,
                                            report_data_size,
                                            NULL, // opt_params,
                                            0,    // opt_params_size,
                                            report_buffer,
                                            &report_buffer_size);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    oe_report_t parsed_report;
    oeResult = oe_parse_report(report_buffer, report_buffer_size, &parsed_report);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    oeResult = oe_verify_report(report_buffer,
        report_buffer_size,
        NULL);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetReportV2(uint32_t flags)
{
    uint8_t* report_buffer = NULL;
    size_t report_buffer_size = sizeof(report_buffer);
    uint8_t report_data[OE_REPORT_DATA_SIZE] = { 0 };
    size_t report_data_size = OE_REPORT_DATA_SIZE;

    oe_result_t oeResult = oe_get_report_v2(flags,
                                            report_data,
                                            report_data_size,
                                            NULL, // opt_params,
                                            0,    // opt_params_size,
                                            &report_buffer,
                                            &report_buffer_size);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    oe_report_t parsed_report;
    oeResult = oe_parse_report(report_buffer, report_buffer_size, &parsed_report);
    if (oeResult != OE_OK) {
        oe_free_report(report_buffer);
        return OE_FAILURE;
    }

    oeResult = oe_verify_report(report_buffer,
        report_buffer_size,
        NULL);
    oe_free_report(report_buffer);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetTargetInfoV1(uint32_t flags)
{
    uint8_t report_buffer[1024];
    size_t report_buffer_size = sizeof(report_buffer);
    uint8_t report_data[OE_REPORT_DATA_SIZE] = { 0 };
    size_t report_data_size = OE_REPORT_DATA_SIZE;

    oe_result_t oeResult = oe_get_report_v1(flags,
        report_data,
        report_data_size,
        NULL, // opt_params,
        0,    // opt_params_size,
        report_buffer,
        &report_buffer_size);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    /* Get target info size. */
    size_t targetInfoSize = 0;
    oeResult = oe_get_target_info_v1(report_buffer, report_buffer_size, NULL, &targetInfoSize);
    if (oeResult != OE_BUFFER_TOO_SMALL) {
        return OE_FAILURE;
    }
    if (targetInfoSize == 0) {
        return OE_FAILURE;
    }

    uint8_t* targetInfo = (uint8_t*)malloc(targetInfoSize);
    if (targetInfo == NULL) {
        return OE_OUT_OF_MEMORY;
    }
    
    oeResult = oe_get_target_info_v1(report_buffer, report_buffer_size, targetInfo, &targetInfoSize);
    if (oeResult != OE_OK) {
        free(targetInfo);
        return OE_FAILURE;
    }

    oeResult = oe_get_report_v1(flags,
        report_data,
        report_data_size,
        targetInfo,
        targetInfoSize,
        report_buffer,
        &report_buffer_size);
    free(targetInfo);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    oeResult = oe_verify_report(report_buffer, report_buffer_size, NULL);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetTargetInfoV2(uint32_t flags)
{
    uint8_t* report_buffer = NULL;
    size_t report_buffer_size = sizeof(report_buffer);
    uint8_t report_data[OE_REPORT_DATA_SIZE] = { 0 };
    size_t report_data_size = OE_REPORT_DATA_SIZE;

    oe_result_t oeResult = oe_get_report_v2(flags,
        report_data,
        report_data_size,
        NULL, // opt_params,
        0,    // opt_params_size,
        &report_buffer,
        &report_buffer_size);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    size_t targetInfoSize = 0;
    void* targetInfo = NULL;
    oeResult = oe_get_target_info_v2(report_buffer, report_buffer_size, &targetInfo, &targetInfoSize);
    oe_free_report(report_buffer);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }
    if (targetInfoSize == 0) {
        return OE_FAILURE;
    }

    oeResult = oe_get_report_v2(flags,
        report_data,
        report_data_size,
        targetInfo,
        targetInfoSize,
        &report_buffer,
        &report_buffer_size);
    oe_free_target_info(targetInfo);
    if (oeResult != OE_OK) {
        oe_free_report(report_buffer);
        return OE_FAILURE;
    }

    oeResult = oe_verify_report(report_buffer, report_buffer_size, NULL);
    oe_free_report(report_buffer);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetSealKeyV1(int policy)
{
    oe_result_t oeResult;
    size_t keySize = 0;
    size_t keyInfoSize = 0;
    uint8_t key[16];
    uint8_t keyInfo[512];

    /* Test getting sizes. */
    keySize = 0;
    oeResult = oe_get_seal_key_by_policy_v1(
        (oe_seal_policy_t)policy,
        NULL,
        &keySize,
        NULL,
        &keyInfoSize);
    if (oeResult != OE_BUFFER_TOO_SMALL) {
        return OE_FAILURE;
    }
    /* Size required is platform specific. Make sure the test can handle it. */
    if (keySize > sizeof(key) || keySize == 0) {
        return OE_FAILURE;
    }
    if (keyInfoSize > sizeof(keyInfo) || keyInfoSize == 0) {
        return OE_FAILURE;
    }

    /* Test getting key without getting key info. */
    oeResult = oe_get_seal_key_by_policy_v1(
        (oe_seal_policy_t)policy,
        key,
        &keySize,
        NULL,
        &keyInfoSize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    /* Test getting key and key info. */
    oeResult = oe_get_seal_key_by_policy_v1(
        (oe_seal_policy_t)policy,
        key,
        &keySize,
        keyInfo,
        &keyInfoSize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    /* Test getting key size by key info. */
    keySize = 0;
    oeResult = oe_get_seal_key_v1(keyInfo, keyInfoSize, NULL, &keySize);
    if (oeResult != OE_BUFFER_TOO_SMALL) {
        return OE_FAILURE;
    }
    if (keySize < sizeof(key)) {
        return OE_FAILURE;
    }

    /* Test getting key by key info. */
    oeResult = oe_get_seal_key_v1(keyInfo, keyInfoSize, key, &keySize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetSealKeyV2(int policy)
{
    oe_result_t oeResult;
    size_t keySize = 0;
    size_t keyInfoSize = 0;
    uint8_t* key;
    uint8_t* keyInfo;

    /* Test getting key without getting key info. */
    oeResult = oe_get_seal_key_by_policy_v2(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        NULL,
        &keyInfoSize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }
    oe_free_key(key, NULL);
    if (keySize == 0) {
        return OE_FAILURE;
    }

    /* Test getting key and key info. */
    oeResult = oe_get_seal_key_by_policy_v2(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        &keyInfo,
        &keyInfoSize);
    if (oeResult != OE_OK) {      
        return OE_FAILURE;
    }
    oe_free_key(key, NULL);

    /* Test getting key by key info. */
    oeResult = oe_get_seal_key_v2(keyInfo, keyInfoSize, &key, &keySize);
    oe_free_key(key, keyInfo);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    return OE_OK;
}

oe_result_t ecall_TestOEGetPublicKey(int policy)
{
    oe_result_t oeResult;
    size_t keySize = 0;
    size_t keySize2 = 0;
    size_t keyInfoSize = 0;
    uint8_t* key;
    uint8_t* key2;
    uint8_t* keyInfo;
    oe_result_t tcpsResult;

    /* Test getting key without getting key info. */
    oeResult = oe_get_public_key_by_policy(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        NULL,
        &keyInfoSize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }
    oe_free_key(key, NULL);
    if (keySize == 0) {
        return OE_FAILURE;
    }

    /* Test getting key and key info. */
    oeResult = oe_get_public_key_by_policy(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        &keyInfo,
        &keyInfoSize);
    if (oeResult != OE_OK) {      
        return OE_FAILURE;
    }

    /* Test getting same key by key info. */
    tcpsResult = OE_OK;
    oeResult = oe_get_public_key(keyInfo, keyInfoSize, &key2, &keySize2);
    if (oeResult != OE_OK) {
        oe_free_key(key, keyInfo);
        return OE_FAILURE;
    }

    /* Test that the keys are the same. */
    if (keySize != keySize2 ||
        memcmp(key, key2, keySize) != 0) {
        tcpsResult = OE_FAILURE;
    }

    oe_free_key(key, NULL);
    oe_free_key(key2, keyInfo);
    return tcpsResult;
}

oe_result_t ecall_TestOEGetPrivateKey(int policy)
{
    oe_result_t oeResult;
    size_t keySize = 0;
    size_t keySize2 = 0;
    size_t keyInfoSize = 0;
    uint8_t* key;
    uint8_t* key2;
    uint8_t* keyInfo;
    oe_result_t tcpsResult;

    /* Test getting key without getting key info. */
    oeResult = oe_get_private_key_by_policy(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        NULL,
        &keyInfoSize);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }
    oe_free_key(key, NULL);
    if (keySize == 0) {
        return OE_FAILURE;
    }

    /* Test getting key and key info. */
    oeResult = oe_get_private_key_by_policy(
        (oe_seal_policy_t)policy,
        &key,
        &keySize,
        &keyInfo,
        &keyInfoSize);
    if (oeResult != OE_OK) {      
        return OE_FAILURE;
    }

    /* Test getting same key by key info. */
    tcpsResult = OE_OK;
    oeResult = oe_get_private_key(keyInfo, keyInfoSize, &key2, &keySize2);
    if (oeResult != OE_OK) {
        oe_free_key(key, keyInfo);
        return OE_FAILURE;
    }

    /* Test that the keys are the same. */
    if (keySize != keySize2 ||
        memcmp(key, key2, keySize) != 0) {
        tcpsResult = OE_FAILURE;
    }

    oe_free_key(key, NULL);
    oe_free_key(key2, keyInfo);
    return tcpsResult;
}

void* ecall_OEHostMalloc(int size)
{
    return oe_host_malloc(size);
}

void* ecall_OEHostCalloc(int nmemb, int size)
{
    return oe_host_calloc(nmemb, size);
}

void* ecall_OEHostRealloc(void* ptr, int size)
{
    return oe_host_realloc(ptr, size);
}

char* ecall_OEHostStrndup(char* buff, int size)
{
    return oe_host_strndup(buff, size);
}

void ecall_OEHostFree(void* ptr)
{
    oe_host_free(ptr);
}

uint64_t TestOEExceptionHandler(
    oe_exception_record_t* exception_context)
{
    return 0xFFFFFFFF;
}

oe_result_t ecall_TestOEExceptions()
{
    oe_result_t result;
        
    /* Verify that we can add a handler. */
    result = oe_add_vectored_exception_handler(
        TRUE,
        TestOEExceptionHandler);
    if (result != OE_OK) {
        return OE_FAILURE;
    }

    /* Verify that duplicates are not allowed. */
    result = oe_add_vectored_exception_handler(
        TRUE,
        TestOEExceptionHandler);
    if (result != OE_INVALID_PARAMETER) {
        return OE_FAILURE;
    }

    /* Verify that we can remove an existing handler. */
    result = oe_remove_vectored_exception_handler(TestOEExceptionHandler);
    if (result != OE_OK) {
        return OE_FAILURE;
    }

    /* Verify that we correctly handle non-existant handlers. */
    result = oe_remove_vectored_exception_handler(TestOEExceptionHandler);
    if (result != OE_INVALID_PARAMETER) {
        return OE_FAILURE;
    }

    return OE_OK;
}

typedef void(*oe_ecall_func_t)(
    const uint8_t* input_buffer,
    size_t input_buffer_size,
    uint8_t* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written);

extern oe_ecall_func_t _oe_ecalls_table[];

oe_result_t ecall_TestOcall(void)
{
    oe_result_t oeResult = ocall_DoNothing();
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }

    int input = 1;
    int output = 0;
    oeResult = ocall_ReturnInputArgument(&output, input);
    if (oeResult != OE_OK) {
        return OE_FAILURE;
    }
    if (input != output) {
        return OE_FAILURE;
    }
    return OE_OK;
}
