// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/str.h>
#include <stdio.h>
#include <sys/stat.h>
#include "../host/sgx/enclave.h"
#include "oe_err.h"
#include "oeinfo.h"

// Options loaded from .conf file. Uninitialized fields contain the maximum
// integer value for the corresponding type.
typedef struct _config_file_options
{
    bool debug;
    uint64_t num_heap_pages;
    uint64_t num_stack_pages;
    uint64_t num_tcs;
    uint16_t product_id;
    uint16_t security_version;
} ConfigFileOptions;

#define CONFIG_FILE_OPTIONS_INITIALIZER                                 \
    {                                                                   \
        .debug = false, .num_heap_pages = OE_UINT64_MAX,                \
        .num_stack_pages = OE_UINT64_MAX, .num_tcs = OE_UINT64_MAX,     \
        .product_id = OE_UINT16_MAX, .security_version = OE_UINT16_MAX, \
    }

static int _load_config_file(const char* path, ConfigFileOptions* options)
{
    int rc = -1;
    FILE* is = NULL;
    int r;
    str_t str = STR_NULL_INIT;
    str_t lhs = STR_NULL_INIT;
    str_t rhs = STR_NULL_INIT;
    size_t line = 1;

#ifdef _WIN32
    if (fopen_s(&is, path, "rb") != 0)
#else
    if (!(is = fopen(path, "rb")))
#endif
        goto done;

    if (str_dynamic(&str, NULL, 0) != 0)
        goto done;

    if (str_dynamic(&lhs, NULL, 0) != 0)
        goto done;

    if (str_dynamic(&rhs, NULL, 0) != 0)
        goto done;

    for (; (r = str_fgets(&str, is)) == 0; line++)
    {
        /* Remove leading and trailing whitespace */
        str_ltrim(&str, " \t");
        str_rtrim(&str, " \t\n\r");

        /* Skip comments and empty lines */
        if (str_ptr(&str)[0] == '#' || str_len(&str) == 0)
            continue;

        /* Split string about '=' character */
        if (str_split(&str, " \t=", &lhs, &rhs) != 0 || str_len(&lhs) == 0 ||
            str_len(&rhs) == 0)
        {
            oe_err("%s(%zu): syntax error", path, line);
            goto done;
        }

        /* Handle each setting */
        if (strcmp(str_ptr(&lhs), "Debug") == 0)
        {
            uint64_t value;

            // Debug must be 0 or 1
            if (str_u64(&rhs, &value) != 0 || (value > 1))
            {
                oe_err("%s(%zu): bad value for 'Debug'", path, line);
                goto done;
            }

            options->debug = (bool)value;
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_heap_pages(n))
            {
                oe_err("%s(%zu): bad value for 'NumHeapPages'", path, line);
                goto done;
            }

            options->num_heap_pages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_stack_pages(n))
            {
                oe_err("%s(%zu): bad value for 'NumStackPages'", path, line);
                goto done;
            }

            options->num_stack_pages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_tcs(n))
            {
                oe_err("%s(%zu): bad value for 'NumTCS'", path, line);
                goto done;
            }

            options->num_tcs = n;
        }
        else if (strcmp(str_ptr(&lhs), "ProductID") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !oe_sgx_is_valid_product_id(n))
            {
                oe_err("%s(%zu): bad value for 'ProductID'", path, line);
                goto done;
            }

            options->product_id = n;
        }
        else if (strcmp(str_ptr(&lhs), "SecurityVersion") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !oe_sgx_is_valid_security_version(n))
            {
                oe_err("%s(%zu): bad value for 'SecurityVersion'", path, line);
                goto done;
            }

            options->security_version = n;
        }
        else
        {
            oe_err("%s(%zu): unknown setting: %s", path, line, str_ptr(&rhs));
            goto done;
        }
    }

    rc = 0;

done:

    str_free(&str);
    str_free(&lhs);
    str_free(&rhs);

    if (is)
        fclose(is);

    return rc;
}

static int _load_pem_file(const char* path, void** data, size_t* size)
{
    int rc = -1;
    FILE* is = NULL;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!path || !data || !size)
        goto done;

    /* Get size of this file */
    {
        struct stat st;

        if (stat(path, &st) != 0)
            goto done;

        *size = (size_t)st.st_size;
    }

    /* Allocate memory. We add 1 to null terimate the file since the crypto
     * libraries require null terminated PEM data. */
    if (*size == SIZE_MAX)
        goto done;

    if (!(*data = (uint8_t*)malloc(*size + 1)))
        goto done;

        /* Open the file */
#ifdef _WIN32
    if (fopen_s(&is, path, "rb") != 0)
#else
    if (!(is = fopen(path, "rb")))
#endif
        goto done;

    /* Read file into memory */
    if (fread(*data, 1, *size, is) != *size)
        goto done;

    /* Zero terminate the PEM data. */
    {
        uint8_t* data_tmp = (uint8_t*)*data;
        data_tmp[*size] = 0;
        *size += 1;
    }

    rc = 0;

done:

    if (rc != 0)
    {
        if (data && *data)
        {
            free(*data);
            *data = NULL;
        }

        if (size)
            *size = 0;
    }

    if (is)
        fclose(is);

    return rc;
}

/* Merge configuration file options into enclave properties */
void _merge_config_file_options(
    oe_sgx_enclave_properties_t* properties,
    const ConfigFileOptions* options)
{
    bool initialized = false;

    /* Determine whether the properties are already initialized */
    if (properties->header.size == sizeof(oe_sgx_enclave_properties_t))
        initialized = true;

    /* Initialize properties if not already initialized */
    if (!initialized)
    {
        properties->header.size = sizeof(oe_sgx_enclave_properties_t);
        properties->header.enclave_type = OE_ENCLAVE_TYPE_SGX;
        properties->config.attributes = SGX_FLAGS_MODE64BIT;
    }

    /* Debug option is present */
    if (options->debug)
        properties->config.attributes |= SGX_FLAGS_DEBUG;

    /* If ProductID option is present */
    if (options->product_id != OE_UINT16_MAX)
        properties->config.product_id = options->product_id;

    /* If SecurityVersion option is present */
    if (options->security_version != OE_UINT16_MAX)
        properties->config.security_version = options->security_version;

    /* If NumHeapPages option is present */
    if (options->num_heap_pages != OE_UINT64_MAX)
        properties->header.size_settings.num_heap_pages =
            options->num_heap_pages;

    /* If NumStackPages option is present */
    if (options->num_stack_pages != OE_UINT64_MAX)
        properties->header.size_settings.num_stack_pages =
            options->num_stack_pages;

    /* If NumTCS option is present */
    if (options->num_tcs != OE_UINT64_MAX)
        properties->header.size_settings.num_tcs = options->num_tcs;
}

int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id)
{
    int ret = 1;
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t enc;
    void* pem_data = NULL;
    size_t pem_size;
    ConfigFileOptions options = CONFIG_FILE_OPTIONS_INITIALIZER;
    oe_sgx_enclave_properties_t props;
    oe_sgx_load_context_t context;

    /* Load the configuration file */
    if (conffile && _load_config_file(conffile, &options) != 0)
    {
        oe_err("Failed to load configuration file: %s", conffile);
        goto done;
    }

    /* Load the enclave properties from the enclave.
     * Note that oesign expects that the enclave must already have the .oeinfo
     * section allocated, and cannot currently inject it into the ELF.
     * The load stack (oe_load_enclave_image) requires that the oeinfo_rva be
     * found or fails the load.
     */
    OE_CHECK_ERR(
        oe_read_oeinfo_sgx(enclave, &props),
        "Failed to load enclave: %s: result=%s (%#x)",
        enclave,
        oe_result_str(result),
        result);

    /* Merge the loaded configuration file with existing enclave properties */
    _merge_config_file_options(&props, &options);

    /* Check whether enclave properties are valid */
    {
        const char* field_name;
        OE_CHECK_ERR(
            oe_sgx_validate_enclave_properties(&props, &field_name),
            "Invalid enclave property value: %s",
            field_name);
    }

    /* Initialize the context parameters for measurement only */
    OE_CHECK_ERR(
        oe_sgx_initialize_load_context(
            &context, OE_SGX_LOAD_TYPE_MEASURE, props.config.attributes),
        "oe_sgx_initialize_load_context() failed");

    /* Build an enclave to obtain the MRENCLAVE measurement */
    OE_CHECK_ERR(
        oe_sgx_build_enclave(&context, enclave, &props, &enc),
        "oe_sgx_build_enclave(): result=%s (%#x)",
        oe_result_str(result),
        result);

    if (engine_id)
    {
        /* Initialize the sigstruct object */
        OE_CHECK_ERR(
            oe_sgx_sign_enclave_from_engine(
                &enc.hash,
                props.config.attributes,
                props.config.product_id,
                props.config.security_version,
                engine_id,
                engine_load_path,
                key_id,
                (sgx_sigstruct_t*)props.sigstruct),
            "oe_sgx_sign_enclave_from_engine() failed: result=%s (%#x)",
            oe_result_str(result),
            result);
    }
    else
    {
        /* Load private key into memory */
        if (_load_pem_file(keyfile, &pem_data, &pem_size) != 0)
        {
            oe_err("Failed to load file: %s", keyfile ? keyfile : "NULL");
            goto done;
        }

        /* Initialize the SigStruct object */
        OE_CHECK_ERR(
            oe_sgx_sign_enclave(
                &enc.hash,
                props.config.attributes,
                props.config.product_id,
                props.config.security_version,
                pem_data,
                pem_size,
                (sgx_sigstruct_t*)props.sigstruct),
            "oe_sgx_sign_enclave() failed: result=%s (%#x)",
            oe_result_str(result),
            result);
    }

    /* Create signature section and write out new file */
    OE_CHECK_ERR(
        oe_write_oeinfo_sgx(enclave, &props),
        "oe_write_oeinfo_sgx(): result=%s (%#x)",
        oe_result_str(result),
        result);

    ret = 0;

done:

    if (pem_data)
        free(pem_data);

    oe_sgx_cleanup_load_context(&context);

    return ret;
}
