// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <stdlib.h>
#include <string.h>
#include "../common/sgx/collateral.h"
#include "platform_t.h"

/**
 * Update these default size values as needed.
 * These represent the default buffer sizes that can store their
 * corresponding quote_verification_collateral_args completely.
 * Last updated as per arg-sizes observered as of May 2020.
 */
#define TCBINFO_DEFAULT_SIZE 5000
#define PCK_CRL_DEFAULT_SIZE 600
#define QE_IDENTITY_DEFAULT_SIZE 1500
#define ROOT_CA_CRL_DEFAULT_SIZE 600
#define ALL_ISSUER_CHAIN_DEFAULT_SIZE 3000

/**
 * Pre-allocate memory for the resources that get passed into the
 * oe_get_quote_verification_collateral_ocall. To avoid extra passes
 * needed to take care of OE_BUFFER_TOO_SMALL failures.
 *
 * @param[in] buf The quote verification collateral.
 * [in] def_sizes The default quote verification collateral sizes.
 */
void oe_prealloc_quote_verification_collateral_args(
    oe_get_sgx_quote_verification_collateral_args_t* buf,
    oe_get_sgx_quote_verification_collateral_args_t* default_sizes);

/**
 * This function is called to update the default collateral arg sizes.
 *
 * @param[in] default_sizes The default quote verification collateral sizes.
 * [in] src_args The quote verification collateral.
 */
void oe_update_default_collateral_arg_sizes(
    oe_get_sgx_quote_verification_collateral_args_t* src_args,
    oe_get_sgx_quote_verification_collateral_args_t* default_sizes);

/**
 * Call into host to fetch collateral information.
 */
oe_result_t oe_get_sgx_quote_verification_collateral(
    oe_get_sgx_quote_verification_collateral_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    oe_get_sgx_quote_verification_collateral_args_t in = {0};
    oe_get_sgx_quote_verification_collateral_args_t out = {0};

    /**
     * This variable is used to store default collateral arg sizes.
     */
    static oe_get_sgx_quote_verification_collateral_args_t default_arg_size = {
        0,
        {0},
        0,
        TCBINFO_DEFAULT_SIZE,
        0,
        ALL_ISSUER_CHAIN_DEFAULT_SIZE,
        0,
        PCK_CRL_DEFAULT_SIZE,
        0,
        ALL_ISSUER_CHAIN_DEFAULT_SIZE,
        0,
        ROOT_CA_CRL_DEFAULT_SIZE,
        0,
        QE_IDENTITY_DEFAULT_SIZE,
        0,
        ALL_ISSUER_CHAIN_DEFAULT_SIZE,
        0};

    uint32_t retval;

    if (!args)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* fmspc */
    memcpy(in.fmspc, args->fmspc, sizeof(in.fmspc));
    oe_prealloc_quote_verification_collateral_args(&in, &default_arg_size);

    for (;;)
    {
        memcpy(&out, &in, sizeof(out));

        if (oe_get_quote_verification_collateral_ocall(
                &retval,
                out.fmspc,
                out.tcb_info,
                out.tcb_info_size,
                &out.tcb_info_size,
                out.tcb_info_issuer_chain,
                out.tcb_info_issuer_chain_size,
                &out.tcb_info_issuer_chain_size,
                out.pck_crl,
                out.pck_crl_size,
                &out.pck_crl_size,
                out.root_ca_crl,
                out.root_ca_crl_size,
                &out.root_ca_crl_size,
                out.pck_crl_issuer_chain,
                out.pck_crl_issuer_chain_size,
                &out.pck_crl_issuer_chain_size,
                out.qe_identity,
                out.qe_identity_size,
                &out.qe_identity_size,
                out.qe_identity_issuer_chain,
                out.qe_identity_issuer_chain_size,
                &out.qe_identity_issuer_chain_size) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        if (retval != (oe_result_t)OE_BUFFER_TOO_SMALL)
            break;

        /* tcb_info */
        if (in.tcb_info_size < out.tcb_info_size)
        {
            if (!(in.tcb_info = realloc(in.tcb_info, out.tcb_info_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.tcb_info_size = out.tcb_info_size;
        }

        /* tcb_issuer_chain */
        if (in.tcb_info_issuer_chain_size < out.tcb_info_issuer_chain_size)
        {
            if (!(in.tcb_info_issuer_chain = realloc(
                      in.tcb_info_issuer_chain,
                      out.tcb_info_issuer_chain_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.tcb_info_issuer_chain_size = out.tcb_info_issuer_chain_size;
        }

        /* pck crl */
        if (in.pck_crl_size < out.pck_crl_size)
        {
            if (!(in.pck_crl = realloc(in.pck_crl, out.pck_crl_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.pck_crl_size = out.pck_crl_size;
        }

        /* root ca crl */
        if (in.root_ca_crl_size < out.root_ca_crl_size)
        {
            if (!(in.root_ca_crl =
                      realloc(in.root_ca_crl, out.root_ca_crl_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.root_ca_crl_size = out.root_ca_crl_size;
        }

        /* pck crl issuer chain */
        if (in.pck_crl_issuer_chain_size < out.pck_crl_issuer_chain_size)
        {
            if (!(in.pck_crl_issuer_chain = realloc(
                      in.pck_crl_issuer_chain, out.pck_crl_issuer_chain_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.pck_crl_issuer_chain_size = out.pck_crl_issuer_chain_size;
        }

        /* qe id */
        if (in.qe_identity_size < out.qe_identity_size)
        {
            if (!(in.qe_identity =
                      realloc(in.qe_identity, out.qe_identity_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.qe_identity_size = out.qe_identity_size;
        }

        /* qe id issuer chain*/
        if (in.qe_identity_issuer_chain_size <
            out.qe_identity_issuer_chain_size)
        {
            if (!(in.qe_identity_issuer_chain = realloc(
                      in.qe_identity_issuer_chain,
                      out.qe_identity_issuer_chain_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.qe_identity_issuer_chain_size =
                out.qe_identity_issuer_chain_size;
        }
    }

    OE_CHECK((oe_result_t)retval);

    oe_update_default_collateral_arg_sizes(&out, &default_arg_size);
    *args = out;
    memset(&out, 0, sizeof(out));
    result = OE_OK;

done:

    /* Free buffers. */
    if (result != OE_OK)
    {
        oe_free_sgx_quote_verification_collateral_args(&in);
        oe_free_sgx_quote_verification_collateral_args(&out);
    }

    return result;
}

void oe_prealloc_quote_verification_collateral_args(
    oe_get_sgx_quote_verification_collateral_args_t* buf,
    oe_get_sgx_quote_verification_collateral_args_t* default_sizes)
{
    /* Allocate estimated buffers for quote_verification_collateral_args */

    buf->tcb_info = (uint8_t*)calloc(1, default_sizes->tcb_info_size);

    if (buf->tcb_info)
    {
        buf->tcb_info_size = default_sizes->tcb_info_size;
    }
    else
    {
        goto done;
    }

    buf->tcb_info_issuer_chain =
        (uint8_t*)calloc(1, default_sizes->tcb_info_issuer_chain_size);

    if (buf->tcb_info_issuer_chain)
    {
        buf->tcb_info_issuer_chain_size =
            default_sizes->tcb_info_issuer_chain_size;
    }
    else
    {
        goto done;
    }

    buf->pck_crl = (uint8_t*)calloc(1, default_sizes->pck_crl_size);

    if (buf->pck_crl)
    {
        buf->pck_crl_size = default_sizes->pck_crl_size;
    }
    else
    {
        goto done;
    }

    buf->root_ca_crl = (uint8_t*)calloc(1, default_sizes->root_ca_crl_size);

    if (buf->root_ca_crl)
    {
        buf->root_ca_crl_size = default_sizes->root_ca_crl_size;
    }
    else
    {
        goto done;
    }

    buf->pck_crl_issuer_chain =
        (uint8_t*)calloc(1, default_sizes->pck_crl_issuer_chain_size);

    if (buf->pck_crl_issuer_chain)
    {
        buf->pck_crl_issuer_chain_size =
            default_sizes->pck_crl_issuer_chain_size;
    }
    else
    {
        goto done;
    }

    buf->qe_identity = (uint8_t*)calloc(1, default_sizes->qe_identity_size);

    if (buf->qe_identity)
    {
        buf->qe_identity_size = default_sizes->qe_identity_size;
    }
    else
    {
        goto done;
    }

    buf->qe_identity_issuer_chain =
        (uint8_t*)calloc(1, default_sizes->qe_identity_issuer_chain_size);

    if (buf->qe_identity_issuer_chain)
    {
        buf->qe_identity_issuer_chain_size =
            default_sizes->qe_identity_issuer_chain_size;
    }
    else
    {
        goto done;
    }
    return;
done:
    /*if any of the args remain unallocated, clear all values*/
    oe_free_sgx_quote_verification_collateral_args(buf);
    buf->qe_identity_issuer_chain_size = 0;
    buf->qe_identity_size = 0;
    buf->pck_crl_issuer_chain_size = 0;
    buf->pck_crl_size = 0;
    buf->tcb_info_size = 0;
    buf->tcb_info_issuer_chain_size = 0;
    buf->root_ca_crl_size = 0;
    return;
}

void oe_update_default_collateral_arg_sizes(
    oe_get_sgx_quote_verification_collateral_args_t* src_args,
    oe_get_sgx_quote_verification_collateral_args_t* default_sizes)
{
    /**
     * Update the default sizes after the actual collateral
     * arg sizes have been retrieved
     * */

    default_sizes->tcb_info_size = src_args->tcb_info_size;
    default_sizes->tcb_info_issuer_chain_size =
        src_args->tcb_info_issuer_chain_size;
    default_sizes->root_ca_crl_size = src_args->root_ca_crl_size;
    default_sizes->pck_crl_size = src_args->pck_crl_size;
    default_sizes->pck_crl_issuer_chain_size =
        src_args->pck_crl_issuer_chain_size;
    default_sizes->qe_identity_size = src_args->qe_identity_size;
    default_sizes->qe_identity_issuer_chain_size =
        src_args->qe_identity_issuer_chain_size;
    return;
}

void oe_free_sgx_quote_verification_collateral_args(
    oe_get_sgx_quote_verification_collateral_args_t* args)
{
    if (args)
    {
        free(args->tcb_info);
        free(args->tcb_info_issuer_chain);
        free(args->pck_crl);
        free(args->root_ca_crl);
        free(args->pck_crl_issuer_chain);
        free(args->qe_identity);
        free(args->qe_identity_issuer_chain);
        free(args->host_out_buffer);
    }
}