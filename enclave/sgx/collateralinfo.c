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
 * Call into host to fetch collateral information.
 */
oe_result_t oe_get_sgx_quote_verification_collateral(
    oe_get_sgx_quote_verification_collateral_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    oe_get_sgx_quote_verification_collateral_args_t in = {0};
    oe_get_sgx_quote_verification_collateral_args_t out = {0};
    uint32_t retval;

    if (!args)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* fmspc */
    memcpy(in.fmspc, args->fmspc, sizeof(in.fmspc));

    for (;;)
    {
        memcpy(&out, &in, sizeof(out));
        oe_prealloc_quote_verification_collateral_args(&out);

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
oe_get_sgx_quote_verification_collateral_args_t* buf)
{
    /*These numbers are just estimates of buffer sizes*/
    size_t prealloc_tcb_info_size = 5000;
    size_t prealloc_tcb_info_issuer_chain_size = 3000;
    size_t prealloc_pck_crl_size = 600;
    size_t prealloc_root_ca_crl_size = 600;
    size_t prealloc_pck_crl_issuer_chain_size = 3000;
    size_t prealloc_qe_identity_issuer_chain_size = 3000;
    size_t prealloc_qe_identity_size = 700;
    if(!buf->tcb_info_size)
    {
        buf->tcb_info = (uint8_t *)malloc(prealloc_tcb_info_size);
        if(buf->tcb_info != NULL)
        {
            buf->tcb_info_size = prealloc_tcb_info_size;
            memset(buf->tcb_info,0, buf->tcb_info_size);   
        }
        else
        {
            goto cleanup;
        }        
    }

    if(!buf->tcb_info_issuer_chain_size)
    {
        buf->tcb_info_issuer_chain = (uint8_t *)malloc(prealloc_tcb_info_size);
        if(buf->tcb_info != NULL)
        {
            buf->tcb_info_issuer_chain_size = prealloc_tcb_info_issuer_chain_size;
            memset(buf->tcb_info_issuer_chain,0, buf->tcb_info_issuer_chain_size);    
        }
        else
        {
            goto cleanup;
        }
    }

    if(!buf->pck_crl_size)
    {
        buf->pck_crl = (uint8_t *)malloc(prealloc_pck_crl_size);
        if(buf->pck_crl != NULL)
        {
            buf->pck_crl_size = prealloc_pck_crl_size;
            memset(buf->pck_crl,0, buf->pck_crl_size);
        }
        else
        {
            goto cleanup;
        }
    }

    if(!buf->root_ca_crl_size)
    {
        buf->root_ca_crl = (uint8_t *)malloc(prealloc_root_ca_crl_size);
        if(buf->root_ca_crl != NULL)
        {
            buf->root_ca_crl_size = prealloc_root_ca_crl_size;
            memset(buf->root_ca_crl,0, buf->root_ca_crl_size);
        }
        else
        {
            goto cleanup;
        }
    }

    if(!buf->pck_crl_issuer_chain_size)
    {
        buf->pck_crl_issuer_chain = (uint8_t *)malloc(prealloc_pck_crl_issuer_chain_size);
        if(buf->pck_crl_issuer_chain != NULL)
        {
            buf->pck_crl_issuer_chain_size = 
            prealloc_pck_crl_issuer_chain_size;
            memset(buf->pck_crl_issuer_chain,0, buf->pck_crl_issuer_chain_size
            );
        }
        else
        {
            goto cleanup;
        }
    }

    if(!buf->qe_identity_size)
    {   
        buf->qe_identity = (uint8_t *)malloc(prealloc_qe_identity_size);
        if(buf->qe_identity != NULL)
        {
            buf->qe_identity_size = prealloc_qe_identity_size;
            memset(buf->qe_identity,0, buf->qe_identity_size);
        }
        else
        {
            goto cleanup;
        }
    }   

    if(!buf->qe_identity_issuer_chain_size)
    {
        buf->qe_identity_issuer_chain = (uint8_t *)malloc(prealloc_qe_identity_issuer_chain_size);
        if(buf->qe_identity_issuer_chain != NULL)
        {
            buf->qe_identity_issuer_chain_size = prealloc_qe_identity_issuer_chain_size;
            memset(buf->qe_identity_issuer_chain,0, buf->qe_identity_issuer_chain_size);
        }
        else
        {
            goto cleanup;
        }
    }
    return;
cleanup:
            oe_free_sgx_quote_verification_collateral_args(buf);
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