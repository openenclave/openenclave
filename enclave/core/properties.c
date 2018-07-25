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

OE_CHECK_SIZE(sizeof(oe_sgx_enclave_properties_t), 1856);
