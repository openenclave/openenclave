// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/corelibc/stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/sgx/revocation.h"
#include "internal_t.h"

/**
 * Call into host to fetch revocation information.
 */
oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args)
{
    oe_result_t result = OE_FAILURE;
    oe_get_revocation_info_args_t in;
    oe_get_revocation_info_args_t out;
    uint32_t retval;

    if (!args)
        OE_RAISE(OE_FAILURE);

    /* Verify the crl_urls. */
    if (args->num_crl_urls != 2 || !args->crl_urls[0] || !args->crl_urls[1])
        OE_RAISE(OE_FAILURE);

    memset(&in, 0, sizeof(in));

    /* fmspc */
    memcpy(in.fmspc, args->fmspc, sizeof(in.fmspc));

    /* crl_urls */
    memcpy(in.crl_urls, args->crl_urls, sizeof(in.crl_urls));
    in.num_crl_urls = args->num_crl_urls;

    for (;;)
    {
        memcpy(&out, &in, sizeof(out));

        if (oe_get_revocation_info_ocall(
                &retval,
                out.fmspc,
                out.num_crl_urls,
                out.crl_urls[0],
                out.crl_urls[1],
                out.crl_urls[2],
                out.tcb_info,
                out.tcb_info_size,
                &out.tcb_info_size,
                out.tcb_issuer_chain,
                out.tcb_issuer_chain_size,
                &out.tcb_issuer_chain_size,
                out.crl[0],
                out.crl_size[0],
                &out.crl_size[0],
                out.crl[1],
                out.crl_size[1],
                &out.crl_size[1],
                out.crl[2],
                out.crl_size[2],
                &out.crl_size[2],
                out.crl_issuer_chain[0],
                out.crl_issuer_chain_size[0],
                &out.crl_issuer_chain_size[0],
                out.crl_issuer_chain[1],
                out.crl_issuer_chain_size[1],
                &out.crl_issuer_chain_size[1],
                out.crl_issuer_chain[2],
                out.crl_issuer_chain_size[2],
                &out.crl_issuer_chain_size[2]) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        if (retval != (oe_result_t)OE_BUFFER_TOO_SMALL)
            break;

oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("** CASE1                                                  **\n");
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("\n");

        /* tcb_info */
        if (in.tcb_info_size < out.tcb_info_size)
        {
            if (!(in.tcb_info = realloc(in.tcb_info, out.tcb_info_size)))
                OE_RAISE(OE_OUT_OF_MEMORY);

            in.tcb_info_size = out.tcb_info_size;
        }

oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("** CASE2                                                  **\n");
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("\n");
        /* tcb_issuer_chain */
        if (in.tcb_issuer_chain_size < out.tcb_issuer_chain_size)
        {
            if (!(in.tcb_issuer_chain =
                      realloc(in.tcb_issuer_chain, out.tcb_issuer_chain_size)))
            {
                OE_RAISE(OE_OUT_OF_MEMORY);
            }

            in.tcb_issuer_chain_size = out.tcb_issuer_chain_size;
        }

oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("** CASE3                                                  **\n");
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("\n");
        /* crl */
        for (size_t i = 0; i < OE_COUNTOF(in.crl); i++)
        {
            if (in.crl_size[i] < out.crl_size[i])
            {
                if (!(in.crl[i] = realloc(in.crl[i], out.crl_size[i])))
                    OE_RAISE(OE_OUT_OF_MEMORY);

                in.crl_size[i] = out.crl_size[i];
            }
        }

oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("** CASE4                                                  **\n");
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("\n");
        /* crl_issuer_chain */
        for (size_t i = 0; i < OE_COUNTOF(in.crl_issuer_chain); i++)
        {
            if (in.crl_issuer_chain_size[i] < out.crl_issuer_chain_size[i])
            {
                if (!(in.crl_issuer_chain[i] = realloc(
                          in.crl_issuer_chain[i],
                          out.crl_issuer_chain_size[i])))
                {
                    OE_RAISE(OE_OUT_OF_MEMORY);
                }

                in.crl_issuer_chain_size[i] = out.crl_issuer_chain_size[i];
            }
        }
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("** DONE                                                   **\n");
oe_printf("************************************************************\n");
oe_printf("************************************************************\n");
oe_printf("\n");
    }

    OE_CHECK((oe_result_t)retval);

    *args = out;
    memset(&out, 0, sizeof(out));
    result = OE_OK;

done:

    /* Free out buffer. */
    if (result != OE_OK)
    {
        free(out.tcb_info);
        free(out.tcb_issuer_chain);

        for (size_t i = 0; i < OE_COUNTOF(out.crl); i++)
            free(out.crl[i]);

        for (size_t i = 0; i < OE_COUNTOF(out.crl_issuer_chain); i++)
            free(out.crl_issuer_chain[i]);
    }

    return result;
}

void oe_cleanup_get_revocation_info_args(oe_get_revocation_info_args_t* args)
{
    if (args)
    {
        free(args->tcb_info);
        free(args->tcb_issuer_chain);

        for (size_t i = 0; i < OE_COUNTOF(args->crl); i++)
            free(args->crl[i]);

        for (size_t i = 0; i < OE_COUNTOF(args->crl_issuer_chain); i++)
            free(args->crl_issuer_chain[i]);

        free(args->buffer);
    }
}
