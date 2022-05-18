// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include "../common.h"
#include "config_id_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc < 3)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [with_kss_flags | no_kss_flags]\n",
            argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    const bool with_kss_flags = strcmp(argv[2], "with_kss_flags") == 0;

    oe_sgx_enclave_setting_config_data mandatory_config_data_setting = {
        {0}, original_config_svn, false /* ignore_if_unsupported */};
    memcpy(
        mandatory_config_data_setting.config_id,
        original_config_id,
        sizeof(mandatory_config_data_setting.config_id));
    oe_enclave_setting_t mandatory_settings;
    mandatory_settings.setting_type = OE_SGX_ENCLAVE_CONFIG_DATA;
    mandatory_settings.u.config_data = &mandatory_config_data_setting;

    oe_sgx_enclave_setting_config_data optional_config_data_setting = {
        {0}, original_config_svn, true /* ignore_if_unsupported */};
    memcpy(
        optional_config_data_setting.config_id,
        original_config_id,
        sizeof(optional_config_data_setting.config_id));
    oe_enclave_setting_t optional_settings;
    optional_settings.setting_type = OE_SGX_ENCLAVE_CONFIG_DATA;
    optional_settings.u.config_data = &optional_config_data_setting;

    if (oe_sgx_is_kss_supported())
    {
        result = oe_create_config_id_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            flags,
            &mandatory_settings,
            1,
            &enclave);
        OE_TEST(result == OE_OK);
        if (oe_sgx_has_quote_provider())
        {
            enclave_test_config_id(enclave, &result);
            OE_TEST(result == OE_OK);
        }
    }
    else
    {
        result = oe_create_config_id_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            flags,
            &optional_settings,
            1,
            &enclave);

        // as config_id settings are optional, enclave creation should return
        // success on images not signed with kss flags on coffee lake machines
        if (!with_kss_flags)
        {
            OE_TEST(result == OE_OK);
            enclave_test_config_id_non_kss(enclave, &result);
            OE_TEST(result == OE_OK);
            if (oe_terminate_enclave(enclave) != OE_OK)
            {
                fprintf(
                    stderr,
                    "oe_terminate_enclave(): failed: result=%d\n",
                    result);
                return 1;
            }
        }
        else // on coffee lake machines enclave images signed with kss flags
             // cannot be loaded
        {
            OE_TEST(result == OE_UNSUPPORTED);
        }

        result = oe_create_config_id_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            flags,
            &mandatory_settings,
            1,
            &enclave);

        // as platform does not support kss features and config_id settings
        // are mandatory enclave creation should fail
        OE_TEST(result == OE_UNSUPPORTED);
    }

    printf("=== passed all tests (config_id)\n");

    return 0;
}
