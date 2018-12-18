// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/properties.h>
#include <openenclave/internal/defs.h>

OE_CHECK_SIZE(sizeof(oe_enclave_size_settings_t), 24);

OE_STATIC_ASSERT(sizeof(oe_enclave_type_t) == sizeof(uint32_t));

OE_STATIC_ASSERT(OE_OFFSETOF(oe_enclave_properties_header_t, size) == 0);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_properties_header_t, enclave_type) == 4);

OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_enclave_properties_header_t, size_settings) == 8);

OE_CHECK_SIZE(sizeof(oe_enclave_properties_header_t), 32);

OE_CHECK_SIZE(sizeof(oe_sgx_enclave_config_t), 16);

OE_CHECK_SIZE(OE_OFFSETOF(oe_sgx_enclave_properties_t, header), 0);
OE_CHECK_SIZE(OE_OFFSETOF(oe_sgx_enclave_properties_t, config), 32);
OE_CHECK_SIZE(OE_OFFSETOF(oe_sgx_enclave_properties_t, image_info), 48);
OE_CHECK_SIZE(OE_OFFSETOF(oe_sgx_enclave_properties_t, sigstruct), 112);
OE_CHECK_SIZE(sizeof(oe_sgx_enclave_properties_t), 1928);

//
// Declare an invalid oeinfo to ensure .oeinfo section exists
// - This object won't be linked if enclave has the macro defined.
// - If enclave does't have the macro defined, it must go through
//   oesign to update the stucture, which would override the value.
//

OE_SET_ENCLAVE_SGX(
    OE_UINT16_MAX,
    OE_UINT16_MAX,
    false,
    OE_UINT16_MAX,
    OE_UINT16_MAX,
    OE_UINT16_MAX);
