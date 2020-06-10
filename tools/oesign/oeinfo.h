// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/properties.h>

oe_result_t oe_read_oeinfo_sgx(
    const char* path,
    oe_sgx_enclave_properties_t* properties);

oe_result_t oe_write_oeinfo_sgx(
    const char* path,
    const oe_sgx_enclave_properties_t* properties);
