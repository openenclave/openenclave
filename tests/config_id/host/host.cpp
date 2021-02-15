// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "config_id_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc < 2)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [--host-threads n] [--enclave-threads n] "
            "[--ecalls]\n",
            argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    oe_sgx_enclave_setting_config_data config_data_setting_optional = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        2,
        true /* ignore_if_unsupported */};

    oe_sgx_enclave_setting_config_data config_data_setting = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        2,
        false /* ignore_if_unsupported */};

    oe_enclave_setting_t optional_settings;
    optional_settings.setting_type = OE_SGX_ENCLAVE_CONFIG_DATA,
    optional_settings.u.config_data = &config_data_setting_optional;

    oe_enclave_setting_t mandatory_settings;
    mandatory_settings.setting_type = OE_SGX_ENCLAVE_CONFIG_DATA,
    mandatory_settings.u.config_data = &config_data_setting;

    result = oe_create_config_id_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, &optional_settings, 1, &enclave);

    // as config_id settings are optional, enclave creation should return
    // success even enclave is not signed with KSS Flags
    OE_TEST(result == OE_OK);

    if (oe_terminate_enclave(enclave) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave(): failed: result=%d\n", result);
        return 1;
    }

    result = oe_create_config_id_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, &mandatory_settings, 1, &enclave);

    // as enclave is not signed with the KSS Flags and config_id settings are
    // mandatory enclave creation should fail
    OE_TEST(result == OE_UNSUPPORTED);

    printf("=== passed all tests (config_id)\n");

    return 0;
}
