// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OEGENCREDS_H
#define _OEGENCREDS_H

#include <stddef.h>
#include <stdint.h>

int oe_generated_attested_credentials(
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _OEGENCREDS_H */
