// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/build.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/properties.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/signsgx.h>
#include <openenclave/bits/str.h>
#include <stdarg.h>
#include <sys/stat.h>
#include "../host/enclave.h"

static const char* arg0;

OE_PRINTF_FORMAT(1, 2)
void Err(const char* format, ...)
{
    fprintf(stderr, "%s: ", arg0);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");
}

// Replace .so-extension with .signed.so. If there is no .so extension,
// append .signed.so.
static char* _MakeSignedLibName(const char* path)
{
    const char* p;
    mem_t buf = MEM_DYNAMIC_INIT;

    if ((!(p = strrchr(path, '.'))) || (strcmp(p, ".so") != 0))
        p = path + strlen(path);

    mem_append(&buf, path, p - path);
    mem_append(&buf, ".signed.so", 11);

    return mem_steal(&buf);
}

static int _UpdateAndWriteSharedLib(
    const char* path,
    const OE_EnclaveProperties_SGX* properties)
{
    int rc = -1;
    Elf64 elf;
    FILE* os = NULL;

    /* Open ELF file */
    if (Elf64_Load(path, &elf) != 0)
    {
        Err("cannot load ELF file: %s", path);
        goto done;
    }

    /* Verify that this enclave contains required symbols */
    {
        Elf64_Sym sym;

        if (Elf64_FindSymbolByName(&elf, "OE_Main", &sym) != 0)
        {
            Err("OE_Main() undefined");
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_numPages", &sym) != 0)
        {
            Err("__oe_numPages() undefined");
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_baseHeapPage", &sym) != 0)
        {
            Err("__oe_baseHeapPage() undefined");
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_numHeapPages", &sym) != 0)
        {
            Err("__oe_numHeapPages() undefined");
            goto done;
        }

        if (Elf64_FindSymbolByName(&elf, "__oe_virtualBaseAddr", &sym) != 0)
        {
            Err("__oe_virtualBaseAddr() undefined");
            goto done;
        }
    }

    // Update or create a new .oeinfo section.
    if (OE_UpdateEnclaveProperties_SGX(
            &elf, OE_INFO_SECTION_NAME, properties) != OE_OK)
    {
        if (Elf64_AddSection(
                &elf,
                OE_INFO_SECTION_NAME,
                SHT_NOTE,
                properties,
                sizeof(OE_EnclaveProperties_SGX)) != 0)
        {
            Err("failed to add section: %s", OE_INFO_SECTION_NAME);
            goto done;
        }
    }

    /* Write new shared shared library */
    {
        char* p = _MakeSignedLibName(path);

        if (!p)
        {
            Err("bad shared library name: %s", path);
            goto done;
        }

        if (!(os = fopen(p, "wb")))
        {
            Err("failed to open: %s", p);
            goto done;
        }

        if (fwrite(elf.data, 1, elf.size, os) != elf.size)
        {
            Err("failed to write: %s", p);
            goto done;
        }

        fclose(os);
        os = NULL;

        printf("Created %s\n", p);

        free(p);
    }

    rc = 0;

done:

    if (os)
        fclose(os);

    Elf64_Unload(&elf);

    return rc;
}

// Options loaded from .conf file. Unitialized fields contain the maximum
// integer value for the corresponding type.
typedef struct _ConfigFileOptions
{
    uint8_t debug;
    uint64_t numHeapPages;
    uint64_t numStackPages;
    uint64_t numTCS;
    uint16_t productID;
    uint16_t securityVersion;
} ConfigFileOptions;

#define CONFIG_FILE_OPTIONS_INITIALIZER \
    { \
        .debug = OE_MAX_UINT8, \
        .numHeapPages = OE_MAX_UINT64, \
        .numStackPages = OE_MAX_UINT64, \
        .numTCS = OE_MAX_UINT64, \
        .productID = OE_MAX_UINT16, \
        .securityVersion = OE_MAX_UINT16, \
    }

static int _LoadConfigFile(const char* path, ConfigFileOptions* options)
{
    int rc = -1;
    FILE* is = NULL;
    int r;
    str_t str = STR_NULL_INIT;
    str_t lhs = STR_NULL_INIT;
    str_t rhs = STR_NULL_INIT;
    size_t line = 1;

    if (!(is = fopen(path, "rb")))
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
        str_rtrim(&str, " \t\n");

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
            if (str_u64(&rhs, &value) != 0 || (value != 0 && value != 1))
            {
                Err("%s(%zu): bad value for 'Debug'", path, line);
                goto done;
            }

            options->debug = (uint8_t)value;
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !OE_SGXValidNumHeapPages(n))
            {
                Err("%s(%zu): bad value for 'NumHeapPages'", path, line);
                goto done;
            }

            options->numHeapPages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !OE_SGXValidNumStackPages(n))
            {
                Err("%s(%zu): bad value for 'NumStackPages'", path, line);
                goto done;
            }

            options->numStackPages = n;
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            uint64_t n;

            if (str_u64(&rhs, &n) != 0 || !OE_SGXValidNumTCS(n))
            {
                Err("%s(%zu): bad value for 'NumTCS'", path, line);
                goto done;
            }

            options->numTCS = n;
        }
        else if (strcmp(str_ptr(&lhs), "ProductID") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !OE_SGXValidProductID(n))
            {
                Err("%s(%zu): bad value for 'ProductID'", path, line);
                goto done;
            }

            options->productID = n;
        }
        else if (strcmp(str_ptr(&lhs), "SecurityVersion") == 0)
        {
            uint16_t n;

            if (str_u16(&rhs, &n) != 0 || !OE_SGXValidSecurityVersion(n))
            {
                Err("%s(%zu): bad value for 'SecurityVersion'", path, line);
                goto done;
            }

            options->securityVersion = n;
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

static int _LoadFile(const char* path, void** data, size_t* size)
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

        *size = st.st_size;
    }

    /* Allocate memory */
    if (!(*data = (uint8_t*)malloc(*size)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
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

// Load the SGX enclave properties from an enclave's .oeinfo section.
static OE_Result _LoadEnclaveProperties_SGX(
    const char* path,
    OE_EnclaveProperties_SGX* properties)
{
    OE_Result result = OE_UNEXPECTED;
    Elf64 elf = ELF64_INIT;

    if (properties)
        memset(properties, 0, sizeof(OE_EnclaveProperties_SGX));

    /* Check parameters */
    if (!path || !properties)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF image */
    if (Elf64_Load(path, &elf) != 0)
        OE_RAISE(OE_FAILURE);

    /* Load the SGX enclave properties */
    if (OE_LoadEnclaveProperties_SGX(&elf, OE_INFO_SECTION_NAME, properties) !=
        OE_OK)
    {
        OE_RAISE(OE_NOT_FOUND);
    }

    result = OE_OK;

done:

    if (elf.magic == ELF_MAGIC)
        Elf64_Unload(&elf);

    return result;
}

/* Merge configuration file options into enclave properties */
void _MergeConfigFileOptions(
    OE_EnclaveProperties_SGX* properties,
    const char* path,
    const ConfigFileOptions* options)
{
    bool initialized = false;

    /* Determine whether the properties are already initialized */
    if (properties->header.size == sizeof(OE_EnclaveProperties_SGX))
        initialized = true;

    /* Initialize properties if not already initialized */
    if (!initialized)
    {
        properties->header.size = sizeof(OE_EnclaveProperties_SGX);
        properties->header.enclaveType = OE_ENCLAVE_TYPE_SGX;
        properties->config.attributes = SGX_FLAGS_MODE64BIT;
    }

    /* Debug option is present */
    if (options->debug != OE_MAX_UINT8)
        properties->config.attributes |= SGX_FLAGS_DEBUG;

    /* If ProductID option is present */
    if (options->productID != OE_MAX_UINT16)
        properties->config.productID = options->productID;

    /* If SecurityVersion option is present */
    if (options->securityVersion != OE_MAX_UINT16)
        properties->config.securityVersion = options->securityVersion;

    /* If NumHeapPages option is present */
    if (options->numHeapPages != OE_MAX_UINT64)
        properties->header.sizeSettings.numHeapPages = options->numHeapPages;

    /* If NumStackPages option is present */
    if (options->numStackPages != OE_MAX_UINT64)
        properties->header.sizeSettings.numStackPages = options->numStackPages;

    /* If NumTCS option is present */
    if (options->numTCS != OE_MAX_UINT64)
        properties->header.sizeSettings.numTCS = options->numTCS;
}

int main(int argc, const char* argv[])
{
    arg0 = argv[0];
    int ret = 1;
    OE_Result result;
    OE_SGXDevice* dev = NULL;
    const char* enclave;
    const char* conffile;
    const char* keyfile;
    OE_Enclave enc;
    void* pemData = NULL;
    size_t pemSize;
    ConfigFileOptions options = CONFIG_FILE_OPTIONS_INITIALIZER;
    OE_EnclaveProperties_SGX props;
    OE_SHA256 mrenclave;

    /* Check arguments */
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s ENCLAVE CONFFILE KEYFILE\n", arg0);
        exit(1);
    }

    /* Collect arguments */
    enclave = argv[1];
    conffile = argv[2];
    keyfile = argv[3];

    /* Load the enclave properties from the enclave */
    {
        result = _LoadEnclaveProperties_SGX(enclave, &props);

        if (result != OE_OK && result != OE_NOT_FOUND)
        {
            Err("failed to load enclave: %s: result=%u", enclave, result);
            goto done;
        }
    }

    /* Load the configuration file */
    if (_LoadConfigFile(conffile, &options) != 0)
    {
        Err("failed to load configuration file: %s", conffile);
        goto done;
    }

    /* Merge the configuration file options into the enclave properties */
    _MergeConfigFileOptions(&props, conffile, &options);

    /* Check whether enclave properties are valid */
    {
        const char* fieldName;

        if (OE_ValidateEnclaveProperties_SGX(&props, &fieldName) != OE_OK)
        {
            Err("invalid enclave property value: %s", fieldName);
            goto done;
        }
    }

    /* Open the MEASURER to compute MRENCLAVE */
    if (!(dev = __OE_OpenSGXMeasurer()))
    {
        Err("__OE_OpenSGXDriver() failed");
        goto done;
    }

    /* Build an enclave to obtain the MRENCLAVE measurement */
    if ((result = __OE_BuildEnclave(
             dev, enclave, &props, false, false, &enc)) != OE_OK)
    {
        Err("__OE_BuildEnclave(): result=%u", result);
        goto done;
    }

    /* Load private key into memory */
    if (_LoadFile(keyfile, &pemData, &pemSize) != 0)
    {
        Err("Failed to load file: %s", keyfile);
        goto done;
    }

    /* Get the MRENCLAVE value */
    if ((result = dev->gethash(dev, &mrenclave)) != OE_OK)
    {
        Err("Failed to get hash: result=%u", result);
        goto done;
    }

    /* Initialize the SigStruct object */
    if ((result = OE_SignEnclave_SGX(
             &mrenclave,
             props.config.attributes,
             props.config.productID,
             props.config.securityVersion,
             pemData,
             pemSize,
             (SGX_SigStruct*)props.sigstruct)) != OE_OK)
    {
        Err("OE_SignEnclave() failed: result=%u", result);
        goto done;
    }

    /* Create signature section and write out new file */
    if ((result = _UpdateAndWriteSharedLib(enclave, &props)) != OE_OK)
    {
        Err("_UpdateAndWriteSharedLib(): result=%u", result);
        goto done;
    }

    ret = 0;

done:

    if (dev)
        dev->close(dev);

    if (pemData)
        free(pemData);

    return ret;
}
