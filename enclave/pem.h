// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_PEM_H
#define _OE_ENCLAVE_PEM_H

// MBEDTLS has no mechanism for determining the size of the PEM buffer ahead
// of time, so we are forced to use a maximum buffer size. This quantity is
// used in MEBEDTLS program that calls mbedtls_pk_write_key_pem.
#define OE_PEM_MAX_BYTES (16 * 1024)

#endif /* _OE_ENCLAVE_PEM_H */
