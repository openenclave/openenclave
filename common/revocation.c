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

#ifdef OE_USE_LIBSGX

/**
 * Quote validation involves many variable length objects (quotes, crls, tcb
 * info etc). Since malloc is not yet available in liboeenclave, a fixed size
 * thread-safe static buffer is used as storage for these variable length
 * objects during quote attestation.
 * When malloc and free become available, the _static_malloc and _static_free
 * functions can be
 * removed.
 */

/**
 * A chunk_t represents an allocated object. The objects are expected to be
 * deallocated in the reverse order of allocation. This keeps the allocater very
 * simple.
 */
typedef struct _chunk
{
    struct _chunk* next;
    uint8_t data[];
} chunk_t;

static uint8_t _static_buffer[16 * 1024];
static oe_spinlock_t _buffer_lock = OE_SPINLOCK_INITIALIZER;
static chunk_t* _chunk_list = NULL;
static uint8_t* _free_ptr = NULL;

/**
 * _static_malloc allocates object of given size on the static buffer.
 * The object is aligned to void* boundary.
 */
static void* _static_malloc(uint32_t size)
{
    uint32_t aligned_size =
        oe_round_up_to_multiple(size + sizeof(chunk_t), sizeof(void*));
    chunk_t* chunk = NULL;
    uint8_t* p = NULL;

    // First allocation.
    if (_free_ptr == NULL)
        _free_ptr = _static_buffer;

    if (_free_ptr + aligned_size <= _static_buffer + sizeof(_static_buffer))
    {
        // Allocate new chunk
        chunk = (chunk_t*)_free_ptr;
        _free_ptr += aligned_size;
        p = chunk->data;

        // Update linked list.
        chunk->next = _chunk_list;
        _chunk_list = chunk;
    }
    return p;
}

/**
 * Free the last allocated object from the static buffer.
 */
static void _static_free(uint8_t* ptr, uint32_t size)
{
    chunk_t* chunk = (chunk_t*)(ptr - sizeof(chunk_t));
    if (ptr == NULL || chunk != _chunk_list)
        return;

    oe_memset(ptr, 0, size);

    _free_ptr = (uint8_t*)_chunk_list;
    _chunk_list = _chunk_list->next;
}

/**
 * Parse sgx extensions from given cert.
 */
static oe_result_t _parse_sgx_extensions(
    oe_cert_t* leaf_cert,
    ParsedExtensionInfo* parsed_extension_info)
{
    oe_result_t result = OE_FAILURE;

    // The size of buffer required to parse extensions is not known beforehand.
    uint32_t buffer_size = 1024;
    uint32_t previous_buffer_size = buffer_size;
    uint8_t* buffer = NULL;

    buffer = (uint8_t*)_static_malloc(buffer_size);
    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Try parsing the extensions.
    result = ParseSGXExtensions(
        leaf_cert, buffer, &buffer_size, parsed_extension_info);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        // Allocate larger buffer. extensions_buffer_size contains required size
        // of buffer.
        _static_free(buffer, previous_buffer_size);
        buffer = (uint8_t*)_static_malloc(buffer_size);

        result = ParseSGXExtensions(
            leaf_cert, buffer, &buffer_size, parsed_extension_info);
    }

done:
    _static_free(buffer, buffer_size);
    return result;
}

typedef struct _url
{
    char str[256];
} url_t;

/**
 * Get CRL distribution points from given cert.
 */

static oe_result_t _get_crl_distribution_point(oe_cert_t* cert, url_t* url)
{
    oe_result_t result = OE_FAILURE;
    uint64_t buffer_size = 512;
    uint8_t* buffer = _static_malloc(buffer_size);
    uint64_t previous_buffer_size = buffer_size;
    const char** urls = NULL;
    uint64_t num_urls = 0;

    if (buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    result = oe_get_crl_distribution_points(
        cert, &urls, &num_urls, buffer, &buffer_size);

    if (result == OE_BUFFER_TOO_SMALL)
    {
        _static_free(buffer, previous_buffer_size);
        buffer = _static_malloc(buffer_size);
        if (buffer == NULL)
            OE_RAISE(OE_OUT_OF_MEMORY);

        result = oe_get_crl_distribution_points(
            cert, &urls, &num_urls, buffer, &buffer_size);
    }

    if (result == OE_OK)
    {
        // At most 1 distrubtion point is expected.
        if (num_urls != 1)
            OE_RAISE(OE_FAILURE);
        oe_memcpy(url->str, urls[0], oe_strlen(urls[0]) + 1);
        result = OE_OK;
    }

done:
    _static_free(buffer, previous_buffer_size);
    return result;
}

/**
 * Get distribution points of intermediate and leaf certs.
 */
static oe_result_t _get_crl_distribution_points(
    oe_cert_t* intermediate_cert,
    oe_cert_t* leaf_cert,
    oe_get_revocation_info_args_t* revocation_args,
    url_t urls[2])
{
    oe_result_t result = OE_FAILURE;

    if (!intermediate_cert || !leaf_cert || !revocation_args || !urls)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_crl_distribution_point(intermediate_cert, &urls[0]));

    OE_CHECK(_get_crl_distribution_point(leaf_cert, &urls[1]));

    revocation_args->crl_urls[0] = urls[0].str;
    revocation_args->crl_urls[1] = urls[1].str;
    revocation_args->num_crl_urls = 2;

    result = OE_OK;
done:

    return result;
}

/**
 * Macro to validate and copy buffer from host to enclave memory.
 */

#define COPY_TO_ENCLAVE(dst, dst_size, src, src_size)                       \
    do                                                                      \
    {                                                                       \
        if (!src || src_size == 0 || !oe_is_outside_enclave(src, src_size)) \
            OE_RAISE(OE_FAILURE);                                           \
        dst = (uint8_t*)_static_malloc(src_size);                           \
        if (dst == NULL)                                                    \
            OE_RAISE(OE_OUT_OF_MEMORY);                                     \
        oe_memcpy(dst, src, src_size);                                      \
        dst_size = src_size;                                                \
    } while (0)

/**
 * Call into host to fetch revocation information.
 */
static oe_result_t _get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    uint32_t host_args_buffer_size = sizeof(*args);
    uint8_t* host_args_buffer = NULL;
    oe_get_revocation_info_args_t* host_args = NULL;
    oe_get_revocation_info_args_t tmp_args = {0};
    uint8_t* p = NULL;
    uint32_t crlUrlSizes[2] = {0};

    if (args == NULL || args->num_crl_urls != 2 || args->crl_urls[0] == NULL ||
        args->crl_urls[1] == NULL)
        OE_RAISE(OE_FAILURE);

    if (args->num_crl_urls != 2)
        OE_RAISE(OE_FAILURE);

    // Compute size of buffer to allocate in host memory to marshal the
    // arguments.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        crlUrlSizes[i] = oe_strlen(args->crl_urls[i]) + 1;
        host_args_buffer_size += crlUrlSizes[i];
    }

    host_args_buffer = oe_host_malloc(host_args_buffer_size);
    if (host_args_buffer == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    // Copy args struct.
    p = host_args_buffer;
    host_args = (oe_get_revocation_info_args_t*)p;
    *host_args = *args;
    p += sizeof(*host_args);

    // Copy input buffers.
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        host_args->crl_urls[i] = (const char*)p;
        oe_memcpy(p, args->crl_urls[i], crlUrlSizes[i]);
        p += crlUrlSizes[i];
    }

    OE_CHECK(
        oe_ocall(
            OE_OCALL_GET_REVOCATION_INFO,
            (uint64_t)host_args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT));

    // Copy args to prevent TOCTOU issues.
    tmp_args = *host_args;

    if (tmp_args.result != OE_OK)
        OE_RAISE(OE_FAILURE);

    // Ensure that all required outputs exist.
    COPY_TO_ENCLAVE(
        args->tcb_info,
        args->tcb_info_size,
        tmp_args.tcb_info,
        tmp_args.tcb_info_size);
    COPY_TO_ENCLAVE(
        args->tcb_issuer_chain,
        args->tcb_issuer_chain_size,
        tmp_args.tcb_issuer_chain,
        tmp_args.tcb_issuer_chain_size);

    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        COPY_TO_ENCLAVE(
            args->crl[i],
            args->crl_size[i],
            tmp_args.crl[i],
            tmp_args.crl_size[i]);
        COPY_TO_ENCLAVE(
            args->crl_issuer_chain[i],
            args->crl_issuer_chain_size[i],
            tmp_args.crl_issuer_chain[i],
            tmp_args.crl_issuer_chain_size[i]);
    }

    // Check for null terminators.
    if (args->tcb_info[args->tcb_info_size - 1] != 0 ||
        args->tcb_issuer_chain[args->tcb_issuer_chain_size - 1] != 0)
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    for (uint32_t i = 0; i < args->num_crl_urls; ++i)
    {
        if (args->crl[i][args->crl_size[i] - 1] != 0 ||
            args->crl_issuer_chain[i][args->crl_issuer_chain_size[i] - 1] != 0)
            OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    result = OE_OK;
done:
    // Free args buffer and buffer allocated by host.
    if (host_args_buffer)
        oe_host_free(host_args_buffer);

    if (tmp_args.host_out_buffer)
        oe_host_free(tmp_args.host_out_buffer);

    return result;
}

oe_result_t oe_enforce_revocation(
    oe_cert_t* intermediate_cert,
    oe_cert_t* leaf_cert)
{
    oe_result_t result = OE_FAILURE;
    ParsedExtensionInfo parsed_extension_info = {0};
    oe_get_revocation_info_args_t revocation_args = {0};
    oe_cert_chain_t tcb_issuer_chain = {0};
    oe_cert_chain_t crl_issuer_chain[3] = {0};
    oe_parsed_tcb_info_t parsed_tcb_info = {0};
    oe_tcb_level_t platform_tcb_level = {0};
    url_t urls[2] = {0};

    OE_STATIC_ASSERT(
        OE_COUNTOF(crl_issuer_chain) ==
        OE_COUNTOF(revocation_args.crl_issuer_chain));

    oe_spin_lock(&_buffer_lock);

    OE_CHECK(_parse_sgx_extensions(leaf_cert, &parsed_extension_info));
    oe_memcpy(
        revocation_args.fmspc,
        parsed_extension_info.fmspc,
        sizeof(parsed_extension_info.fmspc));
    OE_CHECK(
        _get_crl_distribution_points(
            intermediate_cert, leaf_cert, &revocation_args, urls));

    OE_CHECK(_get_revocation_info(&revocation_args));
    OE_CHECK(
        oe_cert_chain_read_pem(
            &tcb_issuer_chain,
            revocation_args.tcb_issuer_chain,
            revocation_args.tcb_issuer_chain_size));
    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
    {
        result =
            (oe_cert_chain_read_pem(
                &crl_issuer_chain[i],
                revocation_args.crl_issuer_chain[i],
                revocation_args.crl_issuer_chain_size[i]));
    }

    for (uint32_t i = 0; i < OE_COUNTOF(platform_tcb_level.sgx_tcb_comp_svn);
         ++i)
    {
        platform_tcb_level.sgx_tcb_comp_svn[i] =
            parsed_extension_info.compSvn[i];
    }
    platform_tcb_level.pce_svn = parsed_extension_info.pceSvn;
    platform_tcb_level.status = OE_TCB_LEVEL_STATUS_UNKNOWN;

    OE_CHECK(
        oe_parse_tcb_info_json(
            revocation_args.tcb_info,
            revocation_args.tcb_info_size,
            &platform_tcb_level,
            &parsed_tcb_info));

    OE_CHECK(
        oe_verify_tcb_signature(
            parsed_tcb_info.tcb_info_start,
            parsed_tcb_info.tcb_info_size,
            (sgx_ecdsa256_signature_t*)parsed_tcb_info.signature,
            &tcb_issuer_chain));

    result = OE_OK;

done:
    // Memory from the pool must be freed in reverse order.
    for (int32_t i = revocation_args.num_crl_urls - 1; i >= 0; --i)
    {
        _static_free(
            revocation_args.crl_issuer_chain[i],
            revocation_args.crl_issuer_chain_size[i]);
        _static_free(revocation_args.crl[i], revocation_args.crl_size[i]);
    }
    _static_free(
        revocation_args.tcb_issuer_chain,
        revocation_args.tcb_issuer_chain_size);
    _static_free(revocation_args.tcb_info, revocation_args.tcb_info_size);

    for (uint32_t i = 0; i < revocation_args.num_crl_urls; ++i)
        oe_cert_chain_free(&crl_issuer_chain[i]);
    oe_cert_chain_free(&tcb_issuer_chain);

    if (_free_ptr != _static_buffer)
        result = OE_FAILURE;
    _free_ptr = _static_buffer;
    oe_spin_unlock(&_buffer_lock);

    return result;
}

#endif
