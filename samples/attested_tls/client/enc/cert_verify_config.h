// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef ATTLESTED_TLS_ENCLAVE_CONFIG
#define ATTLESTED_TLS_ENCLAVE_CONFIG

#include <openenclave/enclave.h>
#include <stdio.h>
#include "../../common/common.h"
#include "../../common/tls_server_enc_mrenclave.h"
#include "../../common/tls_server_enc_pubkey.h"
#define TLS_ENCLAVE TLS_CLIENT

oe_result_t verify_claim_value(const oe_claim_t* claim);

#endif
