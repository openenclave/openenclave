// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../../common/tls_server_enc_pubkey.h"
#include "tls_server_t.h"

#include <sys/socket.h>

#define ENCLAVE_SECRET_DATA_SIZE 16
// const char* enclave_name = "Enclave1";
