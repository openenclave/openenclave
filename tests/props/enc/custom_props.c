// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

OE_INFO_SECTION_BEGIN
volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx = {
    .header = {.size = sizeof(oe_sgx_enclave_properties_t),
               .enclave_type = OE_ENCLAVE_TYPE_SGX,
               .size_settings = {.num_heap_pages = 512,
                                 .num_stack_pages = 512,
                                 .num_tcs = 4}},
    .config = {.product_id = 1111,
               .security_version = 2222,
               .attributes =
                   OE_SGX_FLAGS_PROVISION_KEY | OE_MAKE_ATTRIBUTES(0, 0)},
    .end_marker = 0xecececececececec};
OE_INFO_SECTION_END
