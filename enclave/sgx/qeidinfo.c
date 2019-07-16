// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../common/sgx/qeidentity.h"
#include "internal_t.h"

/**
 * Call into host to fetch qe identity information.
 */
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args_out)
{
    oe_result_t result = OE_FAILURE;
    const size_t QE_ID_INFO_SIZE = OE_PAGE_SIZE;
    const size_t ISSUER_CHAIN_SIZE = OE_PAGE_SIZE;
    uint32_t retval;
    oe_get_qe_identity_info_args_t args;

    if (args_out == NULL)
        OE_RAISE(OE_FAILURE);

    memset(args_out, 0, sizeof(oe_get_qe_identity_info_args_t));
    memset(&args, 0, sizeof(oe_get_qe_identity_info_args_t));

    if (!(args.qe_id_info = malloc(QE_ID_INFO_SIZE)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!(args.issuer_chain = malloc(ISSUER_CHAIN_SIZE)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    args.qe_id_info_size = QE_ID_INFO_SIZE;
    args.issuer_chain_size = ISSUER_CHAIN_SIZE;

    /* First call (one or more buffers might be too small). */
    if (oe_get_qe_identify_info_ocall(
            &retval,
            args.qe_id_info,
            args.qe_id_info_size,
            &args.qe_id_info_size,
            args.issuer_chain,
            args.issuer_chain_size,
            &args.issuer_chain_size) != OE_OK)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Subsequent calls to expand the buffers as needed. Note that the output
     * buffer sizes returned from the first call might still be too small on
     * the next call since the qe_id_info and issuer_chain could change
     * between calls. To compensate, loop until success.
     */
    while ((oe_result_t)retval == OE_BUFFER_TOO_SMALL)
    {
        if (!(args.qe_id_info = realloc(args.qe_id_info, args.qe_id_info_size)))
        {
            OE_RAISE(OE_OUT_OF_MEMORY);
        }

        if (!(args.issuer_chain =
                  realloc(args.issuer_chain, args.issuer_chain_size)))
        {
            OE_RAISE(OE_OUT_OF_MEMORY);
        }

        if (oe_get_qe_identify_info_ocall(
                &retval,
                args.qe_id_info,
                args.qe_id_info_size,
                &args.qe_id_info_size,
                args.issuer_chain,
                args.issuer_chain_size,
                &args.issuer_chain_size) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }
    }

    if ((oe_result_t)retval != OE_OK)
        OE_RAISE((oe_result_t)retval);

    // Check for null terminators.
    if (args.qe_id_info[args.qe_id_info_size - 1] != 0 ||
        args.issuer_chain[args.issuer_chain_size - 1] != 0)
    {
        OE_RAISE(OE_INVALID_REVOCATION_INFO);
    }

    *args_out = args;
    args.qe_id_info = NULL;
    args.issuer_chain = NULL;

    result = OE_OK;

done:

    if (args.qe_id_info)
        free(args.qe_id_info);

    if (args.issuer_chain)
        free(args.issuer_chain);

    return result;
}

// Cleanup the args structure.
void oe_cleanup_qe_identity_info_args(oe_get_qe_identity_info_args_t* args)
{
    if (!args)
        return;

    // Free buffers on the enclave side.
    free(args->issuer_chain);
    free(args->qe_id_info);
}
