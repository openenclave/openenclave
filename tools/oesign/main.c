// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_TRACE_LEVEL 1
#include <openenclave/bits/aesm.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/build.h>
#include <openenclave/bits/elf.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/mem.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/signsgx.h>
#include <openenclave/bits/str.h>
#include <openenclave/bits/trace.h>
#include <openenclave/host.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>
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
        Err("cannot load ELF file: %s\n", path);
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
    if (OE_UpdateEnclaveProperties_SGX(&elf, OE_INFO_SECTION_NAME, properties) != OE_OK)
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

typedef struct _ConfigFileOptions
{
    bool debug;
    bool debugFound;

    uint64_t numHeapPages;
    bool numHeapPagesFound;

    uint64_t numStackPages;
    bool numStackPagesFound;

    uint64_t numTCS;
    bool numTCSFound;

    uint16_t productID;
    bool productIDFound;

    uint16_t securityVersion;
    bool securityVersionFound;
} ConfigFileOptions;

int LoadConfigFile(const char* path, ConfigFileOptions* options)
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
            uint64_t value = 0;

            if (str_u64(&rhs, &value) != 0)
            {
                Err("%s(%zu): bad value for 'Debug'", path, line);
                goto done;
            }

            if (value)
                options->debug = true;

            options->debugFound = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumHeapPages") == 0)
        {
            if (str_u64(&rhs, &options->numHeapPages) != 0)
            {
                Err("%s(%zu): bad value for 'NumHeapPages'", path, line);
                goto done;
            }

            options->numHeapPagesFound = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumStackPages") == 0)
        {
            if (str_u64(&rhs, &options->numStackPages) != 0)
            {
                Err("%s(%zu): bad value for 'NumStackPages'", path, line);
                goto done;
            }

            options->numStackPagesFound = true;
        }
        else if (strcmp(str_ptr(&lhs), "NumTCS") == 0)
        {
            if (str_u64(&rhs, &options->numTCS) != 0)
            {
                Err("%s(%zu): bad value for 'NumTCS'", path, line);
                goto done;
            }

            options->numTCSFound = true;
        }
        else if (strcmp(str_ptr(&lhs), "ProductID") == 0)
        {
            if (str_u16(&rhs, &options->productID) != 0)
            {
                Err("%s(%zu): bad value for 'ProductID'", path, line);
                goto done;
            }

            options->productIDFound = true;
        }
        else if (strcmp(str_ptr(&lhs), "SecurityVersion") == 0)
        {
            if (str_u16(&rhs, &options->securityVersion) != 0)
            {
                Err("%s(%zu): bad value for 'SecurityVersion'", 
                    path, line);
                goto done;
            }

            options->securityVersionFound = true;
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
    ConfigFileOptions options;
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

    /* Set default options */
    memset(&options, 0, sizeof(ConfigFileOptions));
    options.numHeapPages = 2;
    options.numStackPages = 1;
    options.numTCS = 2;

    /* Load the configuration file into the enclave properties */
    if (LoadConfigFile(conffile, &options) != 0)
    {
        Err("failed to load configuration file: %s", conffile);
        goto done;
    }

    /* Initialize the enclave properties */
    {
        memset(&props, 0, sizeof(OE_EnclaveProperties_SGX));
        props.header.size = sizeof(OE_EnclaveProperties_SGX);
        props.header.enclaveType = OE_ENCLAVE_TYPE_SGX;
        props.config.attributes = SGX_FLAGS_MODE64BIT;
        props.config.productID = options.productID;
        props.config.securityVersion = options.securityVersion;
        props.header.sizeSettings.numHeapPages = options.numHeapPages;
        props.header.sizeSettings.numStackPages = options.numStackPages;
        props.header.sizeSettings.numTCS = options.numTCS;

        if (options.debug)
            props.config.attributes |= SGX_FLAGS_DEBUG;
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

err;
