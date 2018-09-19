// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/utils.h>
#include <stdio.h>
#include "../../../common/quote.h"
#include "../../../common/tcbinfo.h"
#include "../common/args.h"
#include "../common/tests.cpp"

// Macro to get current source position as a string literal.
#define OE_STRINGIFY(x) #x
#define OE_TOSTRING(x) OE_STRINGIFY(x)
#define OE_SOURCE_POS __FILE__ ":" OE_TOSTRING(__LINE__)

// Encode the current source position as a comment to the assembly block. This
// makes each speculation barrier unique and prevents the compiler from merging
// different speculation barriers. Additionally it also allows manual
// verification of l-fences in generated assembly code.
#define OE_SPECULATION_BARRIER() \
    asm volatile("lfence #" OE_SOURCE_POS::: "memory");

// Check that input data lies outside the enclave and that
// fits within max_size. If so, allocate buffer on enclave
// stack and copy.
oe_result_t oe_copy_input(
    void* dst,
    volatile void* src,
    size_t size,
    size_t max_size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (size > max_size || size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!src || !oe_is_outside_enclave((void*)src, size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (dst == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    oe_memcpy(dst, (void*)src, size);

    // Fix for Spectre-v1 requires l-fence to be inserted after bounds
    // validation. E.g. the oe_is_outside_enclave check above is a bounds check.
    // Without the barrier, even when oe_is_outside_enclave is false, the
    // processor can speculatively start executing code as if
    // oe_is_outside_enclave is true, leading to side-channel vulnerabilities.
    OE_SPECULATION_BARRIER();

    result = OE_OK;
done:
    return result;
}

// Buffers are allocated on the stack. Automatically cleaned up.
#define oe_free_buffer(buffer)

#define QUOTE_SIZE_MAX (4 * 1024)
#define PEM_PCK_CERTIFICATE_SIZE_MAX (10 * 1024)
#define PCK_CRL_SIZE_MAX (1 * 1024)
#define TCB_INFO_JSON_SIZE_MAX (1 * 1024)

OE_ECALL void VerifyQuote(void* args_)
{
    oe_result_t result = OE_UNEXPECTED;
    volatile VerifyQuoteArgs* host_arg = (VerifyQuoteArgs*)args_;

    VerifyQuoteArgs enc_arg_obj = {0};
    VerifyQuoteArgs* enc_arg = &enc_arg_obj;
    static uint8_t enc_quote[QUOTE_SIZE_MAX];
    static uint8_t enc_pem_pck_certificate[PEM_PCK_CERTIFICATE_SIZE_MAX];
    static uint8_t enc_pck_crl[PCK_CRL_SIZE_MAX];
    static uint8_t enc_tcb_info_json[TCB_INFO_JSON_SIZE_MAX];

    oe_secure_zero_fill(enc_quote, QUOTE_SIZE_MAX);
    oe_secure_zero_fill(enc_pem_pck_certificate, PEM_PCK_CERTIFICATE_SIZE_MAX);
    oe_secure_zero_fill(enc_pck_crl, PCK_CRL_SIZE_MAX);
    oe_secure_zero_fill(enc_tcb_info_json, TCB_INFO_JSON_SIZE_MAX);

    // Take snapshot of host_arg to prevent TOCTOU issues.
    OE_CHECK(
        oe_copy_input(enc_arg, host_arg, sizeof(*enc_arg), sizeof(*enc_arg)));

    // TODO: How to manage memory for all these buffers?
    // Max size vs actual size vs where to allocate, function stack
    // vs explicit static buffer etc

    // Copy input buffers to enclave memory.
    OE_CHECK(
        oe_copy_input(
            enc_quote, enc_arg->quote, enc_arg->quote_size, QUOTE_SIZE_MAX));

    // Copy optional inputs buffers to enclave memory.
    if (enc_arg->pem_pck_certificate)
        OE_CHECK(
            oe_copy_input(
                enc_pem_pck_certificate,
                enc_arg->pem_pck_certificate,
                enc_arg->pem_pck_certificate_size,
                PEM_PCK_CERTIFICATE_SIZE_MAX));

    if (enc_arg->pck_crl)
        OE_CHECK(
            oe_copy_input(
                enc_pck_crl,
                enc_arg->pck_crl,
                enc_arg->pck_crl_size,
                PCK_CRL_SIZE_MAX));

    if (enc_arg->tcb_info_json)
        OE_CHECK(
            oe_copy_input(
                enc_tcb_info_json,
                enc_arg->tcb_info_json,
                enc_arg->tcb_info_json_size,
                TCB_INFO_JSON_SIZE_MAX));

    // Additional custom validations that can be performed at enclave boundary.
    // ...

    // Force evaluation of all validations.
    OE_SPECULATION_BARRIER();

    OE_CHECK(
        VerifyQuoteImpl(
            enc_quote,
            enc_arg->quote_size,
            enc_pem_pck_certificate,
            enc_arg->pem_pck_certificate_size,
            enc_arg->pck_crl_size ? enc_pck_crl : NULL,
            enc_arg->pck_crl_size,
            enc_arg->tcb_info_json_size ? enc_tcb_info_json : NULL,
            enc_arg->tcb_info_json_size));

    result = OE_OK;

done:
    if (host_arg)
        host_arg->result = result;

    // Free enclave buffers.
    // Make sure to oe_secure_zero_fill any secrets.
    // Secrets ought not to exist at this level.
    oe_free_buffer(enc_quote);
    oe_free_buffer(enc_pem_pck_certificate);
    oe_free_buffer(enc_pck_crl);
    oe_free_buffer(enc_tcb_info_json);
}

#ifdef OE_USE_LIBSGX

OE_ECALL void TestVerifyTCBInfo(VerifyTCBInfoArgs* args)
{
    args->result = oe_parse_tcb_info_json(
        args->tcb_info,
        args->tcb_info_size,
        (oe_tcb_level_t*)args->platform_tcb_level,
        (oe_parsed_tcb_info_t*)args->parsed_tcb_info);
}

#endif

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
