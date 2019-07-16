// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#include <openenclave/bits/result.h>
#include <stdint.h>

/*
**==============================================================================
**
** oe_get_public_key_args_t
**
**==============================================================================
*/
typedef struct _oe_get_public_key_args
{
    oe_result_t result; /* out */

    oe_asymmetric_key_params_t key_params; /* in */
    const uint8_t* key_info;               /* in */
    size_t key_info_size;                  /* in */
    uint8_t* key_buffer;                   /* out */
    size_t key_buffer_size;                /* out */
} oe_get_public_key_args_t;
