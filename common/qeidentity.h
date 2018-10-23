// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

<<<<<<< HEAD
#ifndef _OE_COMMON_QE_IDENTITY_H
#define _OE_COMMON_QE_IDENTITY_H
=======
#ifndef _OE_COMMON_REVOCATION_H
#define _OE_COMMON_REVOCATION_H
>>>>>>> b7ab80e... added QE ID support

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/cert.h>
#include <openenclave/internal/report.h>

OE_EXTERNC_BEGIN

#ifdef OE_USE_LIBSGX

<<<<<<< HEAD
oe_result_t oe_enforce_qe_identity(void);

// Fetch qe identity info using the specified args structure.
oe_result_t oe_get_qe_identity_info(oe_get_qe_identity_info_args_t* args);

// Cleanup the args structure.
void oe_cleanup_qe_identity_info_args(oe_get_qe_identity_info_args_t* args);
=======
oe_result_t oe_enforce_revocation(
    oe_cert_t* leaf_cert,
    oe_cert_t* intermediate_cert,
    oe_cert_chain_t* pck_cert_chain);

// Fetch revocation info using the specified args structure.
oe_result_t oe_get_revocation_info(oe_get_revocation_info_args_t* args);

// Cleanup the args structure.
void oe_cleanup_get_revocation_info_args(oe_get_revocation_info_args_t* args);
>>>>>>> b7ab80e... added QE ID support

#endif

OE_EXTERNC_END

<<<<<<< HEAD
#endif // _OE_COMMON_QE_IDENTITY_H
=======
#endif // _OE_COMMON_REVOCATION_H
>>>>>>> b7ab80e... added QE ID support
