// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../hostthread.h"
#include "sgxquoteprovider.h"

// Define the name of CA
static uint8_t CRL_CA_PROCESSOR[] = "processor";

/**
 * This file manages the dcap_quoteprov shared library.
 * It loads the library during program startup and keeps it loaded until the
 * application exits. Intel's quoting library repeatedly loads and unloads
 * dcap_quoteprov, but this causes a crash in libssl.so. (See
 * https://rt.openssl.org/Ticket/Display.html?user=guest&pass=guest&id=2325).
 * Keeping dcap_quoteprov pinned in memory solves the libssl.so crash.
 */

extern oe_sgx_quote_provider_t provider;

void oe_quote_provider_log(sgx_ql_log_level_t level, const char* message)
{
    const char* level_string = level == 0 ? "ERROR" : "INFO";
    char formatted[1024];

    snprintf(formatted, sizeof(formatted), "[%s]: %s\n", level_string, message);

    formatted[sizeof(formatted) - 1] = 0;

    OE_TRACE_INFO("dcap_quoteprov: %s", formatted);
}

oe_result_t oe_initialize_quote_provider()
{
    oe_result_t result = OE_OK;
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, oe_load_quote_provider);

    if (!provider.handle)
        OE_RAISE_MSG(
            OE_QUOTE_PROVIDER_LOAD_ERROR,
            "oe_initialize_quote_provider failed",
            NULL);
done:
    return result;
}

oe_result_t oe_get_sgx_quote_verification_collateral(
    oe_get_sgx_quote_verification_collateral_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    sgx_plat_error_t r = SGX_PLAT_ERROR_OUT_OF_MEMORY;
    sgx_ql_qve_collateral_t* collateral = NULL;
    uint32_t host_buffer_size = 0;
    uint8_t* p = 0;
    uint8_t* p_end = 0;
    OE_TRACE_INFO("Calling %s\n", __FUNCTION__);

    uint8_t* fmspc = args->fmspc;
    uint16_t fmspc_size = sizeof(args->fmspc);

    OE_CHECK(oe_initialize_quote_provider());

    if (!provider.get_sgx_quote_verification_collateral ||
        !provider.free_sgx_quote_verification_collateral)
    {
        OE_TRACE_WARNING("Warning: Quote verification collateral was not "
                         "supported by quote provider\n");
        result = OE_QUOTE_PROVIDER_CALL_ERROR;
        goto done;
    }

    // fetch collateral information
    r = provider.get_sgx_quote_verification_collateral(
        fmspc, fmspc_size, (char*)CRL_CA_PROCESSOR, &collateral);
    if (r != SGX_PLAT_ERROR_OK || collateral == NULL)
    {
        OE_RAISE(OE_QUOTE_PROVIDER_CALL_ERROR);
    }

    if (collateral->version != SGX_QL_QVE_COLLATERAL_VERSION)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT,
            "Expected version to be %d, but got %d",
            SGX_QL_QVE_COLLATERAL_VERSION,
            collateral->version);
    }

    if (collateral->pck_crl_issuer_chain == NULL ||
        collateral->pck_crl_issuer_chain_size == 0)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT, "pck_crl_issuer_chain is NULL", NULL);
    }
    host_buffer_size += collateral->pck_crl_issuer_chain_size;

    if (collateral->root_ca_crl == NULL || collateral->root_ca_crl_size == 0)
    {
        OE_RAISE_MSG(OE_INVALID_ENDORSEMENT, "root_ca_crl is NULL", NULL);
    }
    host_buffer_size += collateral->root_ca_crl_size;

    if (collateral->pck_crl == NULL || collateral->pck_crl_size == 0)
    {
        OE_RAISE_MSG(OE_INVALID_ENDORSEMENT, "pck_crl is NULL", NULL);
    }
    host_buffer_size += collateral->pck_crl_size;

    if (collateral->tcb_info_issuer_chain == NULL ||
        collateral->tcb_info_issuer_chain_size == 0)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT, "tcb_info_issuer_chain is NULL", NULL);
    }
    host_buffer_size += collateral->tcb_info_issuer_chain_size;

    if (collateral->tcb_info == NULL || collateral->tcb_info_size == 0)
    {
        OE_RAISE_MSG(OE_INVALID_ENDORSEMENT, "tcb_info is NULL", NULL);
    }
    host_buffer_size += collateral->tcb_info_size;

    if (collateral->qe_identity_issuer_chain == NULL ||
        collateral->qe_identity_issuer_chain_size == 0)
    {
        OE_RAISE_MSG(
            OE_INVALID_ENDORSEMENT, "qe_identity_issuer_chain is NULL", NULL);
    }
    host_buffer_size += collateral->qe_identity_issuer_chain_size;

    if (collateral->qe_identity == NULL || collateral->qe_identity_size == 0)
    {
        OE_RAISE_MSG(OE_INVALID_ENDORSEMENT, "qe_identity is NULL", NULL);
    }
    host_buffer_size += collateral->qe_identity_size;

    p = (uint8_t*)calloc(1, host_buffer_size);
    p_end = p + host_buffer_size;
    if (p == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    args->host_out_buffer = p;

    if (collateral->pck_crl_issuer_chain != NULL)
    {
        args->pck_crl_issuer_chain = p;
        args->pck_crl_issuer_chain_size = collateral->pck_crl_issuer_chain_size;
        OE_CHECK(oe_memcpy_s(
            args->pck_crl_issuer_chain,
            args->pck_crl_issuer_chain_size,
            collateral->pck_crl_issuer_chain,
            collateral->pck_crl_issuer_chain_size));
        // Add null terminator
        args->pck_crl_issuer_chain[args->pck_crl_issuer_chain_size - 1] = 0;
        p += args->pck_crl_issuer_chain_size;
        OE_TRACE_INFO(
            "pck_crl_issuer_chain_size = %ld\n",
            args->pck_crl_issuer_chain_size);
        OE_TRACE_INFO(
            "pck_crl_issuer_chain json = \n%s\n", args->pck_crl_issuer_chain);
    }

    if (collateral->root_ca_crl != NULL)
    {
        args->root_ca_crl = p;
        args->root_ca_crl_size = collateral->root_ca_crl_size;
        OE_CHECK(oe_memcpy_s(
            args->root_ca_crl,
            args->root_ca_crl_size,
            collateral->root_ca_crl,
            collateral->root_ca_crl_size));
        // Add null terminator
        args->root_ca_crl[args->root_ca_crl_size - 1] = 0;
        p += args->root_ca_crl_size;
        OE_TRACE_INFO("root_ca_crl_size = %ld\n", args->root_ca_crl_size);
    }

    if (collateral->pck_crl != NULL)
    {
        args->pck_crl = p;
        args->pck_crl_size = collateral->pck_crl_size;
        OE_CHECK(oe_memcpy_s(
            args->pck_crl,
            args->pck_crl_size,
            collateral->pck_crl,
            collateral->pck_crl_size));
        // Add null terminator
        args->pck_crl[args->pck_crl_size - 1] = 0;
        p += args->pck_crl_size;
        OE_TRACE_INFO("pck_crl_size = %ld\n", args->pck_crl_size);
    }

    if (collateral->tcb_info_issuer_chain != NULL)
    {
        args->tcb_info_issuer_chain = p;
        args->tcb_info_issuer_chain_size =
            collateral->tcb_info_issuer_chain_size;
        OE_CHECK(oe_memcpy_s(
            args->tcb_info_issuer_chain,
            args->tcb_info_issuer_chain_size,
            collateral->tcb_info_issuer_chain,
            collateral->tcb_info_issuer_chain_size));
        // Add null terminator
        args->tcb_info_issuer_chain[args->tcb_info_issuer_chain_size - 1] = 0;
        p += args->tcb_info_issuer_chain_size;
        OE_TRACE_INFO("pck_crl_size = %ld\n", args->tcb_info_issuer_chain_size);
    }

    if (collateral->tcb_info != NULL)
    {
        args->tcb_info = p;
        args->tcb_info_size = collateral->tcb_info_size;
        OE_CHECK(oe_memcpy_s(
            args->tcb_info,
            args->tcb_info_size,
            collateral->tcb_info,
            collateral->tcb_info_size));
        // Add null terminator
        args->tcb_info[args->tcb_info_size - 1] = 0;
        p += args->tcb_info_size;
        OE_TRACE_INFO("tcb_info_size = %ld\n", args->tcb_info_size);
    }

    if (collateral->qe_identity_issuer_chain != NULL)
    {
        args->qe_identity_issuer_chain = p;
        args->qe_identity_issuer_chain_size =
            collateral->qe_identity_issuer_chain_size;
        OE_CHECK(oe_memcpy_s(
            args->qe_identity_issuer_chain,
            args->qe_identity_issuer_chain_size,
            collateral->qe_identity_issuer_chain,
            collateral->qe_identity_issuer_chain_size));
        // Add null terminator
        args->qe_identity_issuer_chain
            [args->qe_identity_issuer_chain_size - 1] = 0;
        p += args->qe_identity_issuer_chain_size;
        OE_TRACE_INFO(
            "qe_identity_issuer_chain_size = %ld\n",
            args->qe_identity_issuer_chain_size);
    }

    if (collateral->qe_identity != NULL)
    {
        args->qe_identity = p;
        args->qe_identity_size = collateral->qe_identity_size;
        OE_CHECK(oe_memcpy_s(
            args->qe_identity,
            args->qe_identity_size,
            collateral->qe_identity,
            collateral->qe_identity_size));
        // Add null terminator
        args->qe_identity[args->qe_identity_size - 1] = 0;
        p += args->qe_identity_size;
        OE_TRACE_INFO("qe_identity_size = %ld\n", args->qe_identity_size);
    }

    if (p != p_end)
    {
        OE_RAISE(OE_UNEXPECTED);
    }

    result = OE_OK;
done:
    if (collateral != NULL)
    {
        provider.free_sgx_quote_verification_collateral(collateral);
    }

    return result;
}

void oe_free_sgx_quote_verification_collateral_args(
    oe_get_sgx_quote_verification_collateral_args_t* args)
{
    if (args)
    {
        if (args->host_out_buffer)
            free(args->host_out_buffer);
    }
}