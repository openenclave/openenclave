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

typedef struct _optional_bool
{
    bool has_value;
    bool value;
} optional_bool_t;

typedef struct _optional_uint64
{
    bool has_value;
    uint64_t value;
} optional_uint64_t;

typedef struct _optional_uint16
{
    bool has_value;
    uint16_t value;
} optional_uint16_t;

// Options loaded from .conf file. Uninitialized fields contain the maximum
// integer value for the corresponding type.
typedef struct _config_file_options
{
    optional_bool_t debug;
    optional_uint64_t num_heap_pages;
    optional_uint64_t num_stack_pages;
    optional_uint64_t num_tcs;
    optional_uint16_t product_id;
    optional_uint16_t security_version;
} config_file_options_t;

static int _load_config_file(const char* path, config_file_options_t* options)
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

            if (options->debug.has_value)
            {
                oe_err("%s(%zu): Duplicate 'Debug' value provided", path, line);
                goto done;
            }

            // Debug must be 0 or 1
            if (str_u64(&rhs, &value) != 0 || (value > 1))
            {
                oe_err("%s(%zu): 'Debug' value must be 0 or 1", path, line);
                goto done;
            }

            options->debug.value = (bool)value;
            options->debug.has_value = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            uint64_t n;

            if (options->num_heap_pages.has_value)
            {
                oe_err(
                    "%s(%zu): Duplicate 'NumHeapPages' value provided",
                    path,
                    line);
                goto done;
            }

            if (str_ptr(&rhs)[0] == '-' || str_u64(&rhs, &n) != 0 ||
                !oe_sgx_is_valid_num_heap_pages(n))
            {
                oe_err(
                    "%s(%zu): bad value for 'NumHeapPages': %s",
                    path,
                    line,
                    str_ptr(&rhs));
                goto done;
            }

            options->num_heap_pages.value = n;
            options->num_heap_pages.has_value = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            uint64_t n;

            if (options->num_stack_pages.has_value)
            {
                oe_err(
                    "%s(%zu): Duplicate 'NumStackPages' value provided",
                    path,
                    line);
                goto done;
            }

            if (str_ptr(&rhs)[0] == '-' || str_u64(&rhs, &n) != 0 ||
                !oe_sgx_is_valid_num_stack_pages(n))
            {
                oe_err(
                    "%s(%zu): bad value for 'NumStackPages': %s",
                    path,
                    line,
                    str_ptr(&rhs));
                goto done;
            }

            options->num_stack_pages.value = n;
            options->num_stack_pages.has_value = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            uint64_t n;

            if (options->num_tcs.has_value)
            {
                oe_err(
                    "%s(%zu): Duplicate 'NumTCS' value provided", path, line);
                goto done;
            }

            if (str_ptr(&rhs)[0] == '-' || str_u64(&rhs, &n) != 0 ||
                !oe_sgx_is_valid_num_tcs(n))
            {
                oe_err(
                    "%s(%zu): bad value for 'NumTCS': %s",
                    path,
                    line,
                    str_ptr(&rhs));
                goto done;
            }

            options->num_tcs.value = n;
            options->num_tcs.has_value = true;
        }
        else if (strcmp(str_ptr(&lhs), "ProductID") == 0)
        {
            uint16_t n;

            if (options->product_id.has_value)
            {
                oe_err(
                    "%s(%zu): Duplicate 'ProductID' value provided",
                    path,
                    line);
                goto done;
            }

            if (str_ptr(&rhs)[0] == '-' || str_u16(&rhs, &n) != 0 ||
                !oe_sgx_is_valid_product_id(n))
            {
                oe_err(
                    "%s(%zu): bad value for 'ProductID': %s",
                    path,
                    line,
                    str_ptr(&rhs));
                goto done;
            }

            options->product_id.value = n;
            options->product_id.has_value = true;
        }
        else if (strcmp(str_ptr(&lhs), "SecurityVersion") == 0)
        {
            uint16_t n;

            if (options->security_version.has_value)
            {
                oe_err(
                    "%s(%zu): Duplicate 'SecurityVersion' value provided",
                    path,
                    line);
                goto done;
            }

            if (str_ptr(&rhs)[0] == '-' || str_u16(&rhs, &n) != 0 ||
                !oe_sgx_is_valid_security_version(n))
            {
                oe_err(
                    "%s(%zu): bad value for 'SecurityVersion': %s",
                    path,
                    line,
                    str_ptr(&rhs));
                goto done;
            }

            options->security_version.value = n;
            options->security_version.has_value = true;
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

static int _load_file(const char* path, void** data, size_t* size)
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

    /* Allocate memory. We add 1 to allow for adding a null terminator
     * since the crypto libraries require null terminated PEM data. */
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

static int _load_pem_file(const char* path, void** data, size_t* size)
{
    int err = _load_file(path, data, size);
    if (err == 0)
    {
        /* Zero terminate the PEM data. */
        uint8_t* data_tmp = (uint8_t*)*data;
        data_tmp[*size] = 0;
        *size += 1;
    }

    return err;
}

/* Merge configuration file options into enclave properties */
void _merge_config_file_options(
    oe_sgx_enclave_properties_t* properties,
    const config_file_options_t* options)
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
    if (options->debug.has_value)
    {
        if (options->debug.value)
            properties->config.attributes |= SGX_FLAGS_DEBUG;
        else
            properties->config.attributes &= ~SGX_FLAGS_DEBUG;
    }

    /* If ProductID option is present */
    if (options->product_id.has_value)
        properties->config.product_id = options->product_id.value;

    /* If SecurityVersion option is present */
    if (options->security_version.has_value)
        properties->config.security_version = options->security_version.value;

    /* If NumHeapPages option is present */
    if (options->num_heap_pages.has_value)
        properties->header.size_settings.num_heap_pages =
            options->num_heap_pages.value;

    /* If NumStackPages option is present */
    if (options->num_stack_pages.has_value)
        properties->header.size_settings.num_stack_pages =
            options->num_stack_pages.value;

    /* If NumTCS option is present */
    if (options->num_tcs.has_value)
        properties->header.size_settings.num_tcs = options->num_tcs.value;
}

oe_result_t _initialize_enclave_properties(
    const char* enclave,
    const char* conffile,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_INVALID_PARAMETER;
    config_file_options_t options = {{0}};

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
        oe_read_oeinfo_sgx(enclave, properties),
        "Failed to load enclave: %s: result=%s (%#x)",
        enclave,
        oe_result_str(result),
        result);

    /* Merge the loaded configuration file with existing enclave properties */
    _merge_config_file_options(properties, &options);

    /* Check whether enclave properties are valid */
    {
        const char* field_name;
        OE_CHECK_ERR(
            oe_sgx_validate_enclave_properties(properties, &field_name),
            "Invalid enclave property value: %s",
            field_name);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t _get_sgx_enclave_hash(
    const char* enclave,
    const oe_sgx_enclave_properties_t* properties,
    OE_SHA256* hash)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t enc;
    oe_sgx_load_context_t context = {0};

    /* Initialize the context parameters for measurement only */
    OE_CHECK_ERR(
        oe_sgx_initialize_load_context(
            &context, OE_SGX_LOAD_TYPE_MEASURE, properties->config.attributes),
        "oe_sgx_initialize_load_context(): result=%s (%#x)",
        oe_result_str(result),
        result);

    /* Build an enclave to obtain the MRENCLAVE measurement */
    OE_CHECK_ERR(
        oe_sgx_build_enclave(&context, enclave, properties, &enc),
        "oe_sgx_build_enclave(): result=%s (%#x)",
        oe_result_str(result),
        result);

    /* Copy the resulting hash out */
    OE_STATIC_ASSERT(sizeof(enc.hash.buf) == 32);
    memcpy(hash->buf, enc.hash.buf, sizeof(enc.hash.buf));
    result = OE_OK;

done:
    oe_sgx_cleanup_load_context(&context);
    return result;
}

oe_result_t _write_digest_file(OE_SHA256* digest, const char* digest_file)
{
    oe_result_t result = OE_UNEXPECTED;
    FILE* file = NULL;

#ifdef _WIN32
    if (fopen_s(&file, digest_file, "wb") != 0)
#else
    if (!(file = fopen(digest_file, "wb")))
#endif
    {
        oe_err("Failed to open: %s", digest_file);
        goto done;
    }

    if (fwrite(digest->buf, 1, sizeof(OE_SHA256), file) != sizeof(OE_SHA256))
    {
        oe_err("Failed to write: %s", digest_file);
        goto done;
    }

    printf("Created %s\n", digest_file);
    result = OE_OK;

done:
    if (file)
    {
        fclose(file);
        file = NULL;
    }
    return result;
}

int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* digest_signature,
    const char* x509,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id)
{
    int ret = 1;
    oe_result_t result = OE_UNEXPECTED;
    void* pem_data = NULL;
    size_t pem_size;
    void* signature_data = NULL;
    size_t signature_size = 0;
    oe_sgx_enclave_properties_t properties;
    OE_SHA256 hash = {0};

    OE_CHECK_NO_TRACE(
        _initialize_enclave_properties(enclave, conffile, &properties));

    OE_CHECK_NO_TRACE(_get_sgx_enclave_hash(enclave, &properties, &hash));

    if (engine_id)
    {
        /* Initialize the sigstruct object */
        OE_CHECK_ERR(
            oe_sgx_sign_enclave_from_engine(
                &hash,
                properties.config.attributes,
                properties.config.product_id,
                properties.config.security_version,
                engine_id,
                engine_load_path,
                key_id,
                (sgx_sigstruct_t*)properties.sigstruct),
            "oe_sgx_sign_enclave_from_engine() failed: result=%s (%#x)",
            oe_result_str(result),
            result);
    }
    else if (digest_signature)
    {
        /* Load the public key from the x509 certificate */
        if (_load_pem_file(x509, &pem_data, &pem_size) != 0)
        {
            oe_err("Failed to load file: %s", x509 ? x509 : "NULL");
            goto done;
        }

        /* Load the digest signature */
        if (_load_file(digest_signature, &signature_data, &signature_size) != 0)
        {
            oe_err(
                "Failed to load file: %s",
                digest_signature ? digest_signature : "NULL");
            goto done;
        }

        /* Initialize the sigstruct with the signature */
        result = oe_sgx_digest_sign_enclave(
            &hash,
            properties.config.attributes,
            properties.config.product_id,
            properties.config.security_version,
            pem_data,
            pem_size,
            signature_data,
            signature_size,
            (sgx_sigstruct_t*)properties.sigstruct);

        if (result != OE_OK)
        {
            if (result == OE_VERIFY_FAILED)
            {
                oe_err("Digest signature cannot be validated against the "
                       "specified enclave configuration using the provided "
                       "certificate.");
            }
            else
            {
                oe_err(
                    "oe_sgx_digest_sign_enclave() failed: result=%s (%#x)",
                    oe_result_str(result),
                    result);
            }
            goto done;
        }
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
                &hash,
                properties.config.attributes,
                properties.config.product_id,
                properties.config.security_version,
                pem_data,
                pem_size,
                (sgx_sigstruct_t*)properties.sigstruct),
            "oe_sgx_sign_enclave() failed: result=%s (%#x)",
            oe_result_str(result),
            result);
    }

    /* Create signature section and write out new file */
    OE_CHECK_ERR(
        oe_write_oeinfo_sgx(enclave, &properties),
        "oe_write_oeinfo_sgx(): result=%s (%#x)",
        oe_result_str(result),
        result);

    ret = 0;

done:
    if (pem_data)
        free(pem_data);

    if (signature_data)
        free(signature_data);

    return ret;
}

int oedigest(const char* enclave, const char* conffile, const char* digest_file)
{
    int ret = -1;
    oe_result_t result = OE_UNEXPECTED;
    oe_sgx_enclave_properties_t properties;
    OE_SHA256 mrenclave = {0};
    OE_SHA256 digest = {0};

    OE_CHECK_NO_TRACE(
        _initialize_enclave_properties(enclave, conffile, &properties));

    OE_CHECK_NO_TRACE(_get_sgx_enclave_hash(enclave, &properties, &mrenclave));

    /* Construct the unsigned sigstruct with the MRENCLAVE and get its digest */
    OE_CHECK_ERR(
        oe_sgx_get_sigstruct_digest(
            &mrenclave,
            properties.config.attributes,
            properties.config.product_id,
            properties.config.security_version,
            &digest),
        "oe_sgx_get_sigstruct_digest(): result=%s (%#x)",
        oe_result_str(result),
        result);

    /* Write the sigstruct digest value to file */
    OE_CHECK_NO_TRACE(_write_digest_file(&digest, digest_file));

    ret = 0;

done:
    return ret;
}
