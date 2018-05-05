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
OE_Result OE_CheckedCopyInputImpl(void** dst, void* src, uint32_t size, uint32_t maxSize, void* buf)
{
    OE_Result result = OE_UNEXPECTED;

    if (size > maxSize || size==0) 
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!src || !OE_IsOutsideEnclave((void*)src, size))
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_speculation_barrier();

    if (!*dst) {
        // Buffer created and supplied via buf.
        if(!buf)
            OE_RAISE(OE_OUT_OF_MEMORY);
        *dst = buf;
    }

    OE_Memcpy(*dst, (void*)src, size);
    result = OE_OK;
done:
    return result;    
}


#define OE_CheckedCopyInput(dst, src, size, maxSize)        \
    OE_CHECK(OE_CheckedCopyInputImpl((void**)&(dst), (void*)src, size, maxSize, \
        !dst ? __builtin_alloca(size < maxSize ? size : maxSize) : NULL))

// Buffers are allocated on the stack. Automatically cleaned up.
#define OE_FreeBuffer(buffer)

#define QUOTE_SIZE_MAX (4 * 1024)
#define PEM_PCK_CERTIFICATE_SIZE_MAX (10 * 1024)
#define PCK_CRL_SIZE_MAX (1 * 1024)
#define TCB_INFO_JSON_SIZE_MAX (1 * 1024)

OE_Result VerityQuoteImpl(
    const uint8_t* encQuote,
    uint32_t quoteSize,
    const uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
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

    // TODO: How to manage memory for all these buffers?
    // Max size vs actual size vs where to allocate, function stack 
    // vs explicit static buffer etc

    // Copy input buffers to enclave memory.
    OE_CheckedCopyInput(
        encQuote, encArg->quote, encArg->quoteSize, QUOTE_SIZE_MAX);

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

#define OE_QUOTE_VERSION (3)

OE_Result _ParseQuote(const uint8_t* encQuote, uint32_t quoteSize, SGX_Quote** sgxQuote, SGX_ReportBody** reportBody)
{
    OE_Result result = OE_UNEXPECTED;
    
    const uint8_t* p = encQuote;
    const uint8_t* const quoteEnd = encQuote + quoteSize;

    *sgxQuote = NULL;
    *reportBody = NULL;

    *sgxQuote = (SGX_Quote*) p;
    p += sizeof(SGX_Quote);
    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);

    *reportBody = (SGX_ReportBody*) p;
    p += sizeof(SGX_ReportBody);
    if (p > quoteEnd)
        OE_RAISE(OE_QUOTE_PARSE_ERROR);
     

done:
    return result;    
}

OE_Result VerityQuoteImpl(
    const uint8_t* encQuote,
    uint32_t quoteSize,
    const uint8_t* encPemPckCertificate,
    uint32_t pemPckCertificateSize,
    const uint8_t* encPckCrl,
    uint32_t encPckCrlSize,
    const uint8_t* encTcbInfoJson,
    uint32_t encTcbInfoJsonSize)
{
    OE_Result result = OE_UNEXPECTED;
    SGX_Quote* sgxQuote = NULL;
    SGX_ReportBody* reportBody = NULL;

    OE_CHECK(_ParseQuote(encQuote, quoteSize, &sgxQuote, &reportBody));



    

    if (sgxQuote->version != OE_QUOTE_VERSION) {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    /*
    TODO: 
        1. Parse pemPckCertificate.
        2. Parse pckCrl.
        3. Parse tcbInfoJson.
        4. verifyPCKCert.
        5. checkValidityPeriodAndIssuer(crl)
        6. Check crl.getIssuer() == pckCert.getIssuer()
        7. Check isRevoked(pemPckCertificate)
        8. Check fmspc(pckCert).asOctetString() == tcbInfoJson.getFmspc()
        9. Check areLatestElementsOutOfDate(tcbInfoJson, pckCert);
        10. checkRevocation(tcbInfoJson, pckCert)
    */

    goto done;
done:
    return result;
}
