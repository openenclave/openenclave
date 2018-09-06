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
// fits within maxSize. If so, allocate buffer on enclave
// stack and copy.
oe_result_t oe_copy_input(
    void* dst,
    volatile void* src,
    size_t size,
    size_t maxSize)
{
    oe_result_t result = OE_UNEXPECTED;

    if (size > maxSize || size == 0)
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
    volatile VerifyQuoteArgs* hostArg = (VerifyQuoteArgs*)args_;

    VerifyQuoteArgs encArgObj = {0};
    VerifyQuoteArgs* encArg = &encArgObj;
    static uint8_t encQuote[QUOTE_SIZE_MAX];
    static uint8_t encPemPckCertificate[PEM_PCK_CERTIFICATE_SIZE_MAX];
    static uint8_t encPckCrl[PCK_CRL_SIZE_MAX];
    static uint8_t encTcbInfoJson[TCB_INFO_JSON_SIZE_MAX];

    oe_secure_zero_fill(encQuote, QUOTE_SIZE_MAX);
    oe_secure_zero_fill(encPemPckCertificate, PEM_PCK_CERTIFICATE_SIZE_MAX);
    oe_secure_zero_fill(encPckCrl, PCK_CRL_SIZE_MAX);
    oe_secure_zero_fill(encTcbInfoJson, TCB_INFO_JSON_SIZE_MAX);

    // Take snapshot of hostArg to prevent TOCTOU issues.
    OE_CHECK(oe_copy_input(encArg, hostArg, sizeof(*encArg), sizeof(*encArg)));

    // TODO: How to manage memory for all these buffers?
    // Max size vs actual size vs where to allocate, function stack
    // vs explicit static buffer etc

    // Copy input buffers to enclave memory.
    OE_CHECK(
        oe_copy_input(
            encQuote, encArg->quote, encArg->quoteSize, QUOTE_SIZE_MAX));

    // Copy optional inputs buffers to enclave memory.
    if (encArg->pemPckCertificate)
        OE_CHECK(
            oe_copy_input(
                encPemPckCertificate,
                encArg->pemPckCertificate,
                encArg->pemPckCertificateSize,
                PEM_PCK_CERTIFICATE_SIZE_MAX));

    if (encArg->pckCrl)
        OE_CHECK(
            oe_copy_input(
                encPckCrl,
                encArg->pckCrl,
                encArg->pckCrlSize,
                PCK_CRL_SIZE_MAX));

    if (encArg->tcbInfoJson)
        OE_CHECK(
            oe_copy_input(
                encTcbInfoJson,
                encArg->tcbInfoJson,
                encArg->tcbInfoJsonSize,
                TCB_INFO_JSON_SIZE_MAX));

    // Additional custom validations that can be performed at enclave boundary.
    // ...

    // Force evaluation of all validations.
    OE_SPECULATION_BARRIER();

    OE_CHECK(
        VerifyQuoteImpl(
            encQuote,
            encArg->quoteSize,
            encPemPckCertificate,
            encArg->pemPckCertificateSize,
            encArg->pckCrlSize ? encPckCrl : NULL,
            encArg->pckCrlSize,
            encArg->tcbInfoJsonSize ? encTcbInfoJson : NULL,
            encArg->tcbInfoJsonSize));

    result = OE_OK;

done:
    if (hostArg)
        hostArg->result = result;

    // Free enclave buffers.
    // Make sure to oe_secure_zero_fill any secrets.
    // Secrets ought not to exist at this level.
    oe_free_buffer(encQuote);
    oe_free_buffer(encPemPckCertificate);
    oe_free_buffer(encPckCrl);
    oe_free_buffer(encTcbInfoJson);
}

#ifdef OE_USE_LIBSGX

OE_ECALL void TestVerifyTCBInfo(VerifyTCBInfoArgs* args)
{
    args->result = oe_parse_tcb_info_json(
        args->tcbInfo,
        args->tcbInfoSize,
        (oe_tcb_level_t*)args->platformTcbLevel,
        (oe_parsed_tcb_info_t*)args->parsedTcbInfo);
}

#endif

OE_SET_ENCLAVE_SGX(
    0,    /* ProductID */
    0,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
