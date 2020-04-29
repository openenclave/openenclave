// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <getopt.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/str.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "../host/sgx/enclave.h"

#if defined(WIN32)
#define HAS_ENGINE_SUPPORT 0
#else
#define HAS_ENGINE_SUPPORT 1
#endif

static const char* arg0;
int oedump(const char*);
int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id);

OE_PRINTF_FORMAT(1, 2)
void Err(const char* format, ...)
{
    fprintf(stderr, "%s ERROR: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

// Append .signed to the name of the executable to be signed.
static char* _make_signed_lib_name(const char* path)
{
    mem_t buf = MEM_DYNAMIC_INIT;

    mem_append(&buf, path, (size_t)strlen(path));
    mem_append(&buf, ".signed", 8);

    return (char*)mem_steal(&buf);
}

static oe_result_t _update_and_write_signed_exe(
    const char* path,
    const oe_sgx_enclave_properties_t* properties)
{
    oe_result_t rc = OE_FAILURE;
    oe_enclave_image_t oeimage;
    FILE* os = NULL;

    /* Open ELF file */
    if (oe_load_enclave_image(path, &oeimage) != OE_OK)
    {
        Err("cannot load ELF file: %s", path);
        goto done;
    }

    // Update or create a new .oeinfo section.
    if (oe_sgx_update_enclave_properties(
            &oeimage, OE_INFO_SECTION_NAME, properties) != OE_OK)
    {
        {
            Err("section doesn't exist: %s", OE_INFO_SECTION_NAME);
            goto done;
        }
    }

    /* Write new signed executable */
    {
        char* p = _make_signed_lib_name(path);

        if (!p)
        {
            Err("bad executable name: %s", path);
            goto done;
        }

#ifdef _WIN32
        if (fopen_s(&os, p, "wb") != 0)
#else
        if (!(os = fopen(p, "wb")))
#endif
        {
            Err("failed to open: %s", p);
            goto done;
        }

        if (fwrite(oeimage.u.elf.elf.data, 1, oeimage.u.elf.elf.size, os) !=
            oeimage.u.elf.elf.size)
        {
            Err("failed to write: %s", p);
            goto done;
        }

        fclose(os);
        os = NULL;

        printf("Created %s\n", p);

        free(p);
    }

    rc = OE_OK;

done:

    if (os)
        fclose(os);

    oeimage.unload(&oeimage);

    return rc;
}

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

/* Check whether the .conf file is missing required options */
static int _check_for_missing_options(const ConfigFileOptions* options)
{
    int ret = 0;

    if (options->num_heap_pages == OE_UINT64_MAX)
    {
        Err("%s: missing option: NumHeapPages", arg0);
        ret = -1;
    }

    if (options->num_stack_pages == OE_UINT64_MAX)
    {
        Err("%s: missing option: NumStackPages", arg0);
        ret = -1;
    }

    if (options->num_tcs == OE_UINT64_MAX)
    {
        Err("%s: missing option: NumTCS", arg0);
        ret = -1;
    }

    if (options->product_id == OE_UINT16_MAX)
    {
        Err("%s: missing option: ProductID", arg0);
        ret = -1;
    }

    if (options->security_version == OE_UINT16_MAX)
    {
        Err("%s: missing option: SecurityVersion", arg0);
        ret = -1;
    }

    return ret;
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
            Err("%s(%zu): syntax error", path, line);
            goto done;
        }

        /* Handle each setting */
        if (strcmp(str_ptr(&lhs), "Debug") == 0)
        {
            uint64_t value;

            // Debug must be 0 or 1
            if (str_u64(&rhs, &value) != 0 || (value > 1))
            {
                Err("%s(%zu): bad value for 'Debug'", path, line);
                goto done;
            }

            options->debug = (bool)value;
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_heap_pages(n))
            {
                Err("%s(%zu): bad value for 'NumHeapPages'", path, line);
                goto done;
            }

            options->num_heap_pages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_stack_pages(n))
            {
                Err("%s(%zu): bad value for 'NumStackPages'", path, line);
                goto done;
            }

            options->num_stack_pages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !oe_sgx_is_valid_num_tcs(n))
            {
                Err("%s(%zu): bad value for 'NumTCS'", path, line);
                goto done;
            }

            options->num_tcs = n;
        }
        else if (strcmp(str_ptr(&lhs), "ProductID") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !oe_sgx_is_valid_product_id(n))
            {
                Err("%s(%zu): bad value for 'ProductID'", path, line);
                goto done;
            }

            options->product_id = n;
        }
        else if (strcmp(str_ptr(&lhs), "SecurityVersion") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !oe_sgx_is_valid_security_version(n))
            {
                Err("%s(%zu): bad value for 'SecurityVersion'", path, line);
                goto done;
            }

            options->security_version = n;
        }
        else
        {
            Err("%s(%zu): unknown setting: %s", path, line, str_ptr(&rhs));
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

// Load the SGX enclave properties from an enclave's .oeinfo section.
static oe_result_t _sgx_load_enclave_properties(
    const char* path,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_image_t oeimage;

    /* clear ELF magic */
    oeimage.u.elf.elf.magic = 0;

    if (properties)
        memset(properties, 0, sizeof(oe_sgx_enclave_properties_t));

    /* Check parameters */
    if (!path || !properties)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF image */
    OE_CHECK(oe_load_enclave_image(path, &oeimage));

    /* Load the SGX enclave properties */
    OE_CHECK(oe_sgx_load_enclave_properties(
        &oeimage, OE_INFO_SECTION_NAME, properties));

    result = OE_OK;

done:

    if (oeimage.u.elf.elf.magic == ELF_MAGIC)
        oeimage.unload(&oeimage);

    return result;
}

/* Merge configuration file options into enclave properties */
void _merge_config_file_options(
    oe_sgx_enclave_properties_t* properties,
    const char* path,
    const ConfigFileOptions* options)
{
    bool initialized = false;
    OE_UNUSED(path);

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

static const char _usage_gen[] =
    "Usage: %s <command> [options]\n"
    "\n"
    "Commands:\n"
    "    sign  -  Sign the specified enclave.\n"
    "    dump  -  Print out the Open Enclave metadata for the specified "
    "enclave.\n"
    "\n"
    "For help with a specific command, enter \"%s <command> --help\"\n";

static const char _usage_sign[] =
    "Usage: %s sign {--enclave-image | -e} ENCLAVE_IMAGE "
    "{--config-file | -c} CONFIG_FILE {--key-file | -k} KEY_FILE\n"
#if HAS_ENGINE_SUPPORT
    "{{--engine| -n} ENGINE_NAME {--load-path | -p } ENGINE_LOAD_PATH "
    "{--key-id | -i } KEY_ID }\n"
#endif
    "\n"
    "Where:\n"
    "    ENCLAVE_IMAGE -- path of an enclave image file\n"
    "    CONFIG_FILE -- configuration file containing enclave properties\n"
    "    KEY_FILE -- private key file used to digitally sign the image\n"
#if HAS_ENGINE_SUPPORT
    "    ENGINE_NAME -- text name of the engine to use, for example 'pkcs-11'\n"
    "    ENGINE_LOADPATH -- absolute path to the shared object which "
    "implements the engine\n"
    "    KEY_ID -- text string specifying the desired key from the engine\n"
#endif
    "\n"
    "Description:\n"
    "    This utility (1) injects runtime properties into an enclave image "
    "and\n"
    "    (2) digitally signs that image.\n"
    "\n"
    "    The properties are read from the CONFIG_FILE. They override any\n"
    "    properties that were already defined inside the enclave image "
    "through\n"
    "    use of the OE_SET_ENCLAVE_SGX macro. These properties include:\n"
    "\n"
    "        Debug - whether enclave debug mode should be enabled (1) or not "
    "(0)\n"
    "        ProductID - the product identified number\n"
    "        SecurityVersion - the security version number\n"
    "        NumHeapPages - the number of heap pages for this enclave\n"
    "        NumStackPages - the number of stack pages for this enclave\n"
    "        NumTCS - the number of thread control structures for this "
    "enclave\n"
    "\n"
    "    The configuration file contains simple NAME=VALUE entries. For "
    "example:\n"
    "\n"
    "        Debug=1\n"
    "        NumHeapPages=1024\n"
    "\n"
    "    If specified, the key read from KEY_FILE and contains a private RSA "
    "key in PEM\n"
    "    format. The keyfile must contain the following header.\n"
    "\n"
    "        -----BEGIN RSA PRIVATE KEY-----\n"
    "\n"
    "    The resulting image is written to ENCLAVE_IMAGE.signed\n"
    "\n"
#if HAS_ENGINE_SUPPORT
    " Keys may also be received from an openssl engine specified by the "
    "string ENGINE_NAME\n"
    " If they are received from an engine, KEY_ID must be specified rather "
    "than KEY_FILE. \n"
#endif
    "\n";

static const char _usage_dump[] =
    "Usage: %s dump {--enclave-image | -e} ENCLAVE_IMAGE\n"
    "\n"
    "Where:\n"
    "    ENCLAVE_IMAGE -- path of an enclave image file\n"
    "\n"
    "Description:\n"
    "    This option dumps the oeinfo and signature information of an "
    "enclave\n";

int oesign(
    const char* enclave,
    const char* conffile,
    const char* keyfile,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id)
{
    int ret = 1;
    oe_result_t result;
    oe_enclave_t enc;
    void* pem_data = NULL;
    size_t pem_size;
    ConfigFileOptions options = CONFIG_FILE_OPTIONS_INITIALIZER;
    oe_sgx_enclave_properties_t props;
    oe_sgx_load_context_t context;

    /* Load the configuration file */
    if (_load_config_file(conffile, &options) != 0)
    {
        Err("failed to load configuration file: %s", conffile);
        goto done;
    }

    /* Load the enclave properties from the enclave */
    {
        result = _sgx_load_enclave_properties(enclave, &props);

        if (result != OE_OK && result != OE_NOT_FOUND)
        {
            Err("failed to load enclave: %s: result=%s (%u)",
                enclave,
                oe_result_str(result),
                result);
            goto done;
        }

        /* If enclave properties not found, then options must be complete */
        if (result == OE_NOT_FOUND)
        {
            if (_check_for_missing_options(&options) != 0)
                goto done;
        }
    }

    /* Merge the configuration file options into the enclave properties */
    _merge_config_file_options(&props, conffile, &options);

    /* Check whether enclave properties are valid */
    {
        const char* field_name;

        if (oe_sgx_validate_enclave_properties(&props, &field_name) != OE_OK)
        {
            Err("invalid enclave property value: %s", field_name);
            goto done;
        }
    }

    /* Initialize the context parameters for measurement only */
    if (oe_sgx_initialize_load_context(
            &context, OE_SGX_LOAD_TYPE_MEASURE, props.config.attributes) !=
        OE_OK)
    {
        Err("oe_sgx_initialize_load_context() failed");
        goto done;
    }

    /* Build an enclave to obtain the MRENCLAVE measurement */
    if ((result = oe_sgx_build_enclave(&context, enclave, &props, &enc)) !=
        OE_OK)
    {
        Err("oe_sgx_build_enclave(): result=%s (%u)",
            oe_result_str(result),
            result);
        goto done;
    }

    if (engine_id)
    {
        /* Initialize the sigstruct object */
        if ((result = oe_sgx_sign_enclave_from_engine(
                 &enc.hash,
                 props.config.attributes,
                 props.config.product_id,
                 props.config.security_version,
                 engine_id,
                 engine_load_path,
                 key_id,
                 (sgx_sigstruct_t*)props.sigstruct)) != OE_OK)
        {
            Err("oe_sgx_sign_enclave_from_engine() failed: result=%s (%u)",
                oe_result_str(result),
                result);
            goto done;
        }
    }
    else
    {
        /* Load private key into memory */
        if (_load_pem_file(keyfile, &pem_data, &pem_size) != 0)
        {
            Err("Failed to load file: %s", keyfile ? keyfile : "NULL");
            goto done;
        }

        /* Initialize the SigStruct object */
        if ((result = oe_sgx_sign_enclave(
                 &enc.hash,
                 props.config.attributes,
                 props.config.product_id,
                 props.config.security_version,
                 pem_data,
                 pem_size,
                 (sgx_sigstruct_t*)props.sigstruct)) != OE_OK)
        {
            Err("oe_sgx_sign_enclave() failed: result=%s (%u)",
                oe_result_str(result),
                result);
            goto done;
        }
    }

    /* Create signature section and write out new file */
    if ((result = _update_and_write_signed_exe(enclave, &props)) != OE_OK)
    {
        Err("_update_and_write_signed_exe(): result=%s (%u)",
            oe_result_str(result),
            result);
        goto done;
    }

    ret = 0;

done:

    if (pem_data)
        free(pem_data);

    oe_sgx_cleanup_load_context(&context);

    return ret;
}

int dump_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:";

    int c;
    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_dump, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (enclave == NULL)
    {
        Err("Enclave image flag is missing");
        ret = 1;
    }
    if (!ret)
        /* dump oeinfo and signature information */
        ret = oedump(enclave);

done:

    return ret;
}

int sign_parser(int argc, const char* argv[])
{
    int ret = 0;
    const char* enclave = NULL;
    const char* conffile = NULL;
    const char* keyfile = NULL;
#if HAS_ENGINE_SUPPORT
    const char* engine_id = NULL;
    const char* engine_load_path = NULL;
    const char* key_id = NULL;
#endif

    const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"enclave-image", required_argument, NULL, 'e'},
        {"config-file", required_argument, NULL, 'c'},
        {"key-file", required_argument, NULL, 'k'},
#if HAS_ENGINE_SUPPORT
        {"engine", required_argument, NULL, 'n'},
        {"load-path", required_argument, NULL, 'p'},
        {"key-id", required_argument, NULL, 'i'},
#endif
        {NULL, 0, NULL, 0},
    };
    const char short_options[] = "he:c:k:n:p:i:";

    int c;

    if (argc <= 2)
    {
        fprintf(stderr, _usage_sign, argv[0]);
        ret = 1;
        goto done;
    }

    do
    {
        c = getopt_long(
            argc, (char* const*)argv, short_options, long_options, NULL);
        if (c == -1)
        {
            // all the command-line options are parsed
            break;
        }

        switch (c)
        {
            case 'h':
                fprintf(stderr, _usage_sign, argv[0]);
                goto done;
            case 'e':
                enclave = optarg;
                break;
            case 'c':
                conffile = optarg;
                break;
            case 'k':
                keyfile = optarg;
                break;
#if HAS_ENGINE_SUPPORT
            case 'n':
                engine_id = optarg;
                break;
            case 'p':
                engine_load_path = optarg;
                break;
            case 'i':
                key_id = optarg;
                break;
#endif
            case ':':
                // Missing option argument
                ret = 1;
                goto done;
            case '?':
            default:
                // Invalid option
                ret = 1;
                goto done;
        }
    } while (1);

    if (conffile == NULL)
    {
        Err("Config file flag is missing");
        ret = 1;
    }

#if HAS_ENGINE_SUPPORT
    if (keyfile)
    {
        if (engine_id || engine_load_path || key_id)
        {
            Err("if keyfile is specified, engine flags are not allowed");
            ret = 1;
            goto done;
        }
    }
    else
    {
        if (!engine_id || !key_id)
        {
            Err("If keyfile is not specified, you must specify at least both "
                "engineid and keyid");
            ret = 1;
            goto done;
        }
    }
    if (!ret)
    {
        ret = oesign(
            enclave, conffile, keyfile, engine_id, engine_load_path, key_id);
    }
#else
    if (keyfile == NULL)
    {
        Err("Required key file flag is missing");
        ret = 1;
        goto done;
    }
    if (!ret)
    {
        ret = oesign(enclave, conffile, keyfile, NULL, NULL, NULL);
    }
#endif

done:

    return ret;
}

int arg_handler(int argc, const char* argv[])
{
    int ret = 1;
    if ((strcmp(argv[1], "dump") == 0))
        ret = dump_parser(argc, argv);
    else if ((strcmp(argv[1], "sign") == 0))
        ret = sign_parser(argc, argv);
    else
    {
        fprintf(stderr, _usage_gen, argv[0], argv[0]);
        exit(1);
    }
    return ret;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = 1;

    if (argc < 2)
    {
        fprintf(stderr, _usage_gen, argv[0], argv[0]);
        exit(1);
    }

    ret = arg_handler(argc, argv);
    return ret;
}
