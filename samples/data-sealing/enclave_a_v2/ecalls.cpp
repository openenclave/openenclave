// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <common/datasealing_t.h>
#include <common/dispatcher.h>
#include <common/shared.h>
#include <openenclave/enclave.h>

// Declare a static dispatcher object for better organization of enclave-wise
// global variables
static ecall_dispatcher dispatcher;
const char* enclave_name = "Enclave2";

int seal_data(
    int sealPolicy,
    unsigned char opt_mgs[128],
    size_t opt_msg_len,
    unsigned char* data,
    size_t data_size,
    data_t* sealed_data)
{
    return dispatcher.seal_data(
        sealPolicy, opt_mgs, opt_msg_len, data, data_size, sealed_data);
}
int unseal_data(const data_t* sealed_data, data_t* output_data)
{
    return dispatcher.unseal_data(sealed_data, output_data);
}
