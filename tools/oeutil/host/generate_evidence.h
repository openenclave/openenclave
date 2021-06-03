// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include "../../../host/sgx/platformquoteprovider.h"
#include "../oeutil_enc_pubkey.h"

int oeutil_generate_evidence(int argc, const char* argv[]);

#endif // _SGX_QUOTE
