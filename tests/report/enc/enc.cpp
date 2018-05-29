// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include "../../../common/quote.h"
#include "../common/args.h"
#include "../common/tests.cpp"

// Supply unique integer to asm block to prevent the compiler from merging
// different speculation barriers.
#define OE_SPECULATION_BARRIER() \
    asm volatile("lfence " ::"r"(__COUNTER__) : "memory");

// Check that input data lies outside the enclave and that
// fits within maxSize. If so, allocate buffer on enclave
// stack and copy.
OE_Result OE_CopyInput(
    void* dst,
    volatile void* src,
    uint32_t size,
    uint32_t maxSize)
{
    OE_Result result = OE_UNEXPECTED;

    if (size > maxSize || size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!src || !OE_IsOutsideEnclave((void*)src, size))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (dst == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_Memcpy(dst, (void*)src, size);

    // Fix for Spectre-v1 requires lfence to be inserted after bounds
    // validation. E.g. the OE_IsOutsideEnclave check above is a bounds check.
    // Without the barrier, even when OE_IsOutsideEnclave is false, the
    // processor can speculatively start executing code as if
    // OE_IsOutsideEnclave is true, leading to side-channel vulnerabilities.
    OE_SPECULATION_BARRIER();

    result = OE_OK;
done:
    return result;
}

// Buffers are allocated on the stack. Automatically cleaned up.
#define OE_FreeBuffer(buffer)

#define QUOTE_SIZE_MAX (4 * 1024)
#define PEM_PCK_CERTIFICATE_SIZE_MAX (10 * 1024)
#define PCK_CRL_SIZE_MAX (1 * 1024)
#define TCB_INFO_JSON_SIZE_MAX (1 * 1024)

OE_ECALL void VerifyQuote(void* args_)
{
    OE_Result result = OE_UNEXPECTED;
    volatile VerifyQuoteArgs* hostArg = (VerifyQuoteArgs*)args_;

    VerifyQuoteArgs encArgObj = {0};
    VerifyQuoteArgs* encArg = &encArgObj;
    static uint8_t encQuote[QUOTE_SIZE_MAX];
    static uint8_t encPemPckCertificate[PEM_PCK_CERTIFICATE_SIZE_MAX];
    static uint8_t encPckCrl[PCK_CRL_SIZE_MAX];
    static uint8_t encTcbInfoJson[TCB_INFO_JSON_SIZE_MAX];

    OE_SecureZeroFill(encQuote, QUOTE_SIZE_MAX);
    OE_SecureZeroFill(encPemPckCertificate, PEM_PCK_CERTIFICATE_SIZE_MAX);
    OE_SecureZeroFill(encPckCrl, PCK_CRL_SIZE_MAX);
    OE_SecureZeroFill(encTcbInfoJson, TCB_INFO_JSON_SIZE_MAX);

    // Take snapshot of hostArg to prevent TOCTOU issues.
    OE_CHECK(OE_CopyInput(encArg, hostArg, sizeof(*encArg), sizeof(*encArg)));

    // TODO: How to manage memory for all these buffers?
    // Max size vs actual size vs where to allocate, function stack
    // vs explicit static buffer etc

    // Copy input buffers to enclave memory.
    OE_CHECK(
        OE_CopyInput(
            encQuote, encArg->quote, encArg->quoteSize, QUOTE_SIZE_MAX));

    // Copy optional inputs buffers to enclave memory.
    if (encArg->pemPckCertificate)
        OE_CHECK(
            OE_CopyInput(
                encPemPckCertificate,
                encArg->pemPckCertificate,
                encArg->pemPckCertificateSize,
                PEM_PCK_CERTIFICATE_SIZE_MAX));

    if (encArg->pckCrl)
        OE_CHECK(
            OE_CopyInput(
                encPckCrl,
                encArg->pckCrl,
                encArg->pckCrlSize,
                PCK_CRL_SIZE_MAX));

    if (encArg->tcbInfoJson)
        OE_CHECK(
            OE_CopyInput(
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
    // Make sure to OE_SecureZeroFill any secrets.
    // Secrets ought not to exist at this level.
    OE_FreeBuffer(encQuote);
    OE_FreeBuffer(encPemPckCertificate);
    OE_FreeBuffer(encPckCrl);
    OE_FreeBuffer(encTcbInfoJson);
}
