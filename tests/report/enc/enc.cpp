// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include "../common/args.h"
#include "../common/tests.cpp"

// Supply unique integer to asm block to prevent the compiler from merging
// different speculation barriers.
#define oe_speculation_barrier() \
    asm volatile("lfence" ::"r"(__COUNTER__) : "memory");

// Check that input data lies outside the enclave and that
// fits within maxSize. If so, allocate buffer on enclave
// stack and copy.
#define OE_CheckedCopyInput(dst, src, size, maxSize)        \
    do                                                      \
    {                                                       \
        if (!src || !OE_IsOutsideEnclave((void*)src, size)) \
            OE_RAISE(OE_INVALID_PARAMETER);                 \
                                                            \
        if (size > maxSize)                                 \
            OE_RAISE(OE_INVALID_PARAMETER);                 \
                                                            \
        oe_speculation_barrier();                           \
                                                            \
        *(void**)&(dst) = (void*)__builtin_alloca(size);    \
        if (dst == NULL)                                    \
            OE_RAISE(OE_OUT_OF_MEMORY);                     \
        OE_Memcpy((void*)dst, (void*)src, size);            \
    } while (0)

// Buffers are allocated on the stack. Automatically cleaned up.
#define OE_FreeBuffer(buffer)

#define QUOTE_SIZE_MAX (4 * 1024)
#define PEM_PCK_CERTIFICATE_SIZE_MAX (1 * 1024)
#define PCK_CRL_SIZE_MAX (1 * 1024)
#define TCB_INFO_JSON_SIZE_MAX (1 * 1024)

OE_Result VerityQuoteImpl(
    uint8_t* encQuote,
    uint32_t quoteSize,
    uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize);

OE_ECALL void VerifyQuote(void* args_)
{
    OE_Result result = OE_UNEXPECTED;
    volatile VerifyQuoteArgs* hostArg = (VerifyQuoteArgs*)args_;

    const VerifyQuoteArgs* encArg = NULL;
    uint8_t* encQuote = NULL;
    uint8_t* encPemPckCertificate = NULL;
    uint8_t* encPckCrl = NULL;
    uint8_t* encTcbInfoJson = NULL;

    // Take snapshot of hostArg to prevent TOCTOU issues.
    OE_CheckedCopyInput(encArg, hostArg, sizeof(*encArg), sizeof(*encArg));

    // Copy input buffers to enclave memory.
    OE_CheckedCopyInput(
        encQuote, encArg->quote, encArg->quoteSize, QUOTE_SIZE_MAX);

    OE_CheckedCopyInput(
        encQuote,
        encArg->quote,
        encArg->quoteSize,
        PEM_PCK_CERTIFICATE_SIZE_MAX);

    // Copy optional inputs buffers to enclave memory.
    if (encArg->pemPckCertificate)
        OE_CheckedCopyInput(
            encPemPckCertificate,
            encArg->pemPckCertificate,
            encArg->pemPckCertificateSize,
            PEM_PCK_CERTIFICATE_SIZE_MAX);

    if (encArg->pckCrl)
        OE_CheckedCopyInput(
            encPckCrl, encArg->pckCrl, encArg->pckCrlSize, PCK_CRL_SIZE_MAX);

    if (encArg->tcbInfoJson)
        OE_CheckedCopyInput(
            encTcbInfoJson,
            encArg->tcbInfoJson,
            encArg->tcbInfoJsonSize,
            TCB_INFO_JSON_SIZE_MAX);

    // Additional custom validations that can be performed at enclave boundary.
    // ...

    // Force evaluation of all validations.
    oe_speculation_barrier();

    // TODO:
    //      Quote validation
    result = VerityQuoteImpl(
        encQuote,
        encArg->quoteSize,
        encPemPckCertificate,
        encArg->pemPckCertificateSize,
        encPckCrl,
        encArg->pckCrlSize,
        encTcbInfoJson,
        encArg->tcbInfoJsonSize);

    if (result == OE_OK)
    {
        // Copy outputs
    }

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

OE_Result VerityQuoteImpl(
    uint8_t* encQuote,
    uint32_t quoteSize,
    uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize)
{
    OE_Result result = OE_UNEXPECTED;
    goto done;
done:
    return result;
}
