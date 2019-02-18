// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../common/dispatcher.h"
#include "../shared.h"
#include "datasealing_t.h"

// Declare a static dispatcher object for better organization of enclave-wise
// global variables
static ecall_dispatcher dispatcher;
const char* enclave_name = "Enclave3";

int seal_data(
    int sealPolicy,
    unsigned char opt_mgs[128],
    size_t opt_msg_len,
    unsigned char* data,
    size_t data_size,
    sealed_data_t** sealed_data,
    size_t* sealed_data_size)
{
    return dispatcher.seal_data(
        sealPolicy,
        opt_mgs,
        opt_msg_len,
        data,
        data_size,
        sealed_data,
        sealed_data_size);
}
int unseal_data(
    sealed_data_t* sealed_data,
    size_t sealed_data_size,
    unsigned char** data,
    size_t* data_size)
{
    return dispatcher.unseal_data(
        sealed_data, sealed_data_size, data, data_size);
}
