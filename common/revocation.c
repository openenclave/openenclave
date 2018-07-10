// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//#define OE_TRACE_LEVEL 2

#include "revocation.h"
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgxcertextensions.h>
#include <openenclave/internal/sha.h>
#include <openenclave/internal/utils.h>
#include "tcbinfo.h"

typedef struct _Chunk
{
    struct _Chunk* next;
    uint8_t data[];
} Chunk;

static uint8_t _QuoteProcessingBuffer[16 * 1024];
static oe_spinlock_t _QuoteProcessingLock = OE_SPINLOCK_INITIALIZER;
static Chunk* _LastAllocatedChunk = NULL;
static uint8_t* _FreePtr = NULL;

static void* _Malloc(uint32_t size)
{
    uint32_t alignedSize =
        oe_round_up_to_multiple(size + sizeof(Chunk), sizeof(void*));
    Chunk* chunk = NULL;
    uint8_t* p = NULL;

    if (_FreePtr == NULL)
        _FreePtr = _QuoteProcessingBuffer;

    if (_FreePtr + alignedSize <=
        _QuoteProcessingBuffer + sizeof(_QuoteProcessingBuffer))
    {
        chunk = (Chunk*)_FreePtr;
        _FreePtr += alignedSize;
        p = chunk->data;
        chunk->next = _LastAllocatedChunk;
        _LastAllocatedChunk = chunk;
    }
    return p;
}

static void _Free(uint8_t* ptr, uint32_t size)
{
    Chunk* chunk = (Chunk*)(ptr - sizeof(Chunk));
    if (ptr == NULL || chunk != _LastAllocatedChunk)
        return;

    // Reverse order of deallocation expected.
    for (uint32_t i = 0; i < size; ++i)
    {
        ptr[i] = 0;
    }
    _FreePtr = (uint8_t*)_LastAllocatedChunk;
    _LastAllocatedChunk = _LastAllocatedChunk->next;
}

oe_result_t _ParseSGXExtensions(
    oe_cert_t* leafCert,
    ParsedExtensionInfo* parsedInfo)
{
    oe_result_t result = OE_FAILURE;
    uint8_t* extensionsBuffer = NULL;
    uint32_t extensionsBufferSize = 1024;
    uint32_t previousSize = extensionsBufferSize;

    while (true)
    {
        extensionsBuffer = (uint8_t*)_Malloc(extensionsBufferSize);
        if (extensionsBuffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        previousSize = extensionsBufferSize;
        result = ParseSGXExtensions(
            leafCert, extensionsBuffer, &extensionsBufferSize, parsedInfo);
        // All the information has been parsed.
        _Free(extensionsBuffer, extensionsBufferSize);

        if (result != OE_BUFFER_TOO_SMALL)
            break;

        // ParseSGXExtensions must return correct size of buffer.
        if (extensionsBufferSize <= previousSize)
            OE_RAISE(OE_FAILURE);
    }
    result = OE_OK;
done:
    return result;
}

static oe_result_t _GetCrlDistributionPoints(
    oe_cert_t* cert,
    const char*** urls,
    uint64_t* numUrls,
    uint8_t** buffer,
    uint64_t* bufferSize)
{
    oe_result_t result = OE_FAILURE;
    size_t previousSize = 0;
    *bufferSize = 128;

    while (true)
    {
        *buffer = _Malloc(*bufferSize);
        if (*buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        previousSize = *bufferSize;
        result = oe_get_crl_distribution_points(
            cert, urls, numUrls, *buffer, bufferSize);
        if (result != OE_BUFFER_TOO_SMALL)
            break;

        _Free(*buffer, *bufferSize);
        if (*bufferSize <= previousSize)
            OE_RAISE(OE_FAILURE);
    }
    result = OE_OK;
done:
    return result;
}

static oe_result_t _GetCrlUrls(
    oe_cert_t* intermediateCert,
    oe_cert_t* leafCert,
    oe_get_revocation_info_args_t* revocationArgs,
    uint8_t** intermediateCertUrlsBuffer,
    uint64_t* intermediateCertUrlsBufferSize,
    uint8_t** leafCertUrlsBuffer,
    uint64_t* leafCertUrlsBufferSize)
{
    oe_result_t result = OE_FAILURE;
    const char** p = NULL;
    const char** intermediateCertUrls = NULL;
    uint64_t intermediateCertNumUrls = 0;

    const char** leafCertUrls = NULL;
    uint64_t leafCertNumUrls = 0;

    if (!intermediateCert || !leafCert || !revocationArgs ||
        !intermediateCertUrlsBuffer || !intermediateCertUrlsBufferSize ||
        !leafCertUrlsBuffer || !leafCertUrlsBufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(
        _GetCrlDistributionPoints(
            intermediateCert,
            &intermediateCertUrls,
            &intermediateCertNumUrls,
            intermediateCertUrlsBuffer,
            intermediateCertUrlsBufferSize));

    OE_CHECK(
        _GetCrlDistributionPoints(
            leafCert,
            &leafCertUrls,
            &leafCertNumUrls,
            leafCertUrlsBuffer,
            leafCertUrlsBufferSize));

    if (intermediateCertNumUrls + leafCertNumUrls >
        OE_COUNTOF(revocationArgs->crlUrls))
        OE_RAISE(OE_FAILURE);

    p = revocationArgs->crlUrls;
    for (uint64_t i = 0; i < intermediateCertNumUrls; ++i)
        *p++ = intermediateCertUrls[i];

    for (uint64_t i = 0; i < leafCertNumUrls; ++i)
        *p++ = leafCertUrls[i];

    revocationArgs->numCrlUrls = intermediateCertNumUrls + leafCertNumUrls;

    result = OE_OK;
done:
    if (result != OE_OK)
    {
        if (*leafCertUrlsBuffer)
            _Free(*leafCertUrlsBuffer, *leafCertUrlsBufferSize);

        if (*intermediateCertUrlsBuffer)
            _Free(*intermediateCertUrlsBuffer, *intermediateCertUrlsBufferSize);
    }

    return result;
}

#define COPY_TO_ENCLAVE(dst, dstSize, src, srcSize)                       \
    do                                                                    \
    {                                                                     \
        if (!src || srcSize == 0 || !oe_is_outside_enclave(src, srcSize)) \
            OE_RAISE(OE_FAILURE);                                         \
        dst = (uint8_t*)_Malloc(srcSize);                                 \
        if (dst == NULL)                                                  \
            OE_RAISE(OE_OUT_OF_MEMORY);                                   \
        oe_memcpy(dst, src, srcSize);                                     \
        dstSize = srcSize;                                                \
    } while (0)

static oe_result_t _GetRevocationInfo(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    uint32_t hostArgsBufferSize = sizeof(*args);
    uint8_t* hostArgsBuffer = NULL;
    oe_get_revocation_info_args_t* hostArgs = NULL;
    oe_get_revocation_info_args_t tmpArgs = {0};
    uint8_t* p = NULL;
    uint32_t crlUrlSizes[2] = {0};

    if (args == NULL || args->numCrlUrls != 2 || args->crlUrls[0] == NULL ||
        args->crlUrls[1] == NULL)
        OE_RAISE(OE_FAILURE);

    if (args->numCrlUrls != 2)
        OE_RAISE(OE_FAILURE);

    for (uint32_t i = 0; i < args->numCrlUrls; ++i)
    {
        crlUrlSizes[i] = oe_strlen(args->crlUrls[i]) + 1;
        hostArgsBufferSize += crlUrlSizes[i];
    }

    hostArgsBuffer = oe_host_malloc(hostArgsBufferSize);
    if (hostArgsBuffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    p = hostArgsBuffer;
    hostArgs = (oe_get_revocation_info_args_t*)p;
    *hostArgs = *args;
    p += sizeof(*hostArgs);

    // Copy input buffers.
    for (uint32_t i = 0; i < args->numCrlUrls; ++i)
    {
        hostArgs->crlUrls[i] = (const char*)p;
        oe_memcpy(p, args->crlUrls[i], crlUrlSizes[i]);
        p += crlUrlSizes[i];
    }

    OE_CHECK(
        oe_ocall(
            OE_FUNC_GET_REVOCATION_INFO,
            (uint64_t)hostArgs,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));
    tmpArgs = *hostArgs;

    if (tmpArgs.result != OE_OK)
        OE_RAISE(OE_FAILURE);

    // Ensure that all required outputs exist.
    COPY_TO_ENCLAVE(
        args->tcbInfo, args->tcbInfoSize, tmpArgs.tcbInfo, tmpArgs.tcbInfoSize);
    COPY_TO_ENCLAVE(
        args->tcbIssuerChain,
        args->tcbIssuerChainSize,
        tmpArgs.tcbIssuerChain,
        tmpArgs.tcbIssuerChainSize);

    for (uint32_t i = 0; i < args->numCrlUrls; ++i)
    {
        COPY_TO_ENCLAVE(
            args->crl[i], args->crlSize[i], tmpArgs.crl[i], tmpArgs.crlSize[i]);
        COPY_TO_ENCLAVE(
            args->crlIssuerChain[i],
            args->crlIssuerChainSize[i],
            tmpArgs.crlIssuerChain[i],
            tmpArgs.crlIssuerChainSize[i]);
    }

    result = OE_OK;
done:
    if (hostArgsBuffer)
        oe_host_free(hostArgsBuffer);

    if (tmpArgs.hostOutBuffer)
        oe_host_free(tmpArgs.hostOutBuffer);

    return result;
}

oe_result_t OE_EnforceRevocation(
    oe_cert_t* intermediateCert,
    oe_cert_t* leafCert)
{
    oe_result_t result = OE_FAILURE;
    ParsedExtensionInfo parsedInfo = {0};
    oe_get_revocation_info_args_t revocationArgs = {0};
    oe_cert_chain_t tcbIssuerChain = {0};
    oe_cert_chain_t crlIssuerChain[3] = {0};

    uint8_t* intermediateCertUrlsBuffer = NULL;
    uint64_t intermediateCertUrlsBufferSize = 0;
    uint8_t* leafCertUrlsBuffer = NULL;
    uint64_t leafCertUrlsBufferSize = 0;
    OE_STATIC_ASSERT(
        OE_COUNTOF(crlIssuerChain) ==
        OE_COUNTOF(revocationArgs.crlIssuerChain));

    oe_spin_lock(&_QuoteProcessingLock);

    OE_CHECK(_ParseSGXExtensions(leafCert, &parsedInfo));
    oe_memcpy(revocationArgs.fmspc, parsedInfo.fmspc, sizeof(parsedInfo.fmspc));
    OE_CHECK(
        _GetCrlUrls(
            intermediateCert,
            leafCert,
            &revocationArgs,
            &intermediateCertUrlsBuffer,
            &intermediateCertUrlsBufferSize,
            &leafCertUrlsBuffer,
            &leafCertUrlsBufferSize));

    OE_CHECK(_GetRevocationInfo(&revocationArgs));

    // Add +1 to size to include \0 as expected by oe_cert_chain_read_pem.
    OE_CHECK(
        oe_cert_chain_read_pem(
            &tcbIssuerChain,
            revocationArgs.tcbIssuerChain,
            revocationArgs.tcbIssuerChainSize + 1));
    for (uint32_t i = 0; i < revocationArgs.numCrlUrls; ++i)
    {
        // Add +1 to size to include \0 as expected by oe_cert_chain_read_pem.
        OE_CHECK(
            oe_cert_chain_read_pem(
                &crlIssuerChain[i],
                revocationArgs.crlIssuerChain[i],
                revocationArgs.crlIssuerChainSize[i] + 1));
    }

    OE_CHECK(
        oe_enforce_tcb_info(
            revocationArgs.tcbInfo,
            revocationArgs.tcbInfoSize,
            &parsedInfo,
            true /* require components to be uptodate. */));

    result = OE_OK;

done:
    // Memory from the pool must be freed in reverse order.
    for (int32_t i = revocationArgs.numCrlUrls - 1; i >= 0; --i)
    {
        _Free(
            revocationArgs.crlIssuerChain[i],
            revocationArgs.crlIssuerChainSize[i]);
        _Free(revocationArgs.crl[i], revocationArgs.crlSize[i]);
    }
    _Free(revocationArgs.tcbIssuerChain, revocationArgs.tcbIssuerChainSize);
    _Free(revocationArgs.tcbInfo, revocationArgs.tcbInfoSize);
    _Free(leafCertUrlsBuffer, leafCertUrlsBufferSize);
    _Free(intermediateCertUrlsBuffer, intermediateCertUrlsBufferSize);

    for (uint32_t i = 0; i < revocationArgs.numCrlUrls; ++i)
        oe_cert_chain_free(&crlIssuerChain[i]);
    oe_cert_chain_free(&tcbIssuerChain);

    if (_FreePtr != _QuoteProcessingBuffer)
        result = OE_FAILURE;
    _FreePtr = _QuoteProcessingBuffer;
    oe_spin_unlock(&_QuoteProcessingLock);

    oe_host_printf("result = %s\n", oe_result_str(result));
    return result;
}
