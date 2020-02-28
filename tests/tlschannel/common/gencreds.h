// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_GENCREDS_H
#define _OE_GENCREDS_H

#include <stddef.h>
#include <stdint.h>

int oe_generate_attested_credentials(
    const char* common_name,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _OE_GENCREDS_H */
