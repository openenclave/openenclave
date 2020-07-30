// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "../../../host/sgx/enclave.h"
#include "../host/sgx/cpuid.h"
#include "props_u.h"

/* Set the Enclave XFRM to Legacy mode */
static uint64_t cur_enclave_xfrm = SGX_XFRM_LEGACY;

static bool _is_avx_supported()
{
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID Leaf 1
    oe_get_cpuid(1, 0, &eax, &ebx, &ecx, &edx);

    // Check if AVX instruction extensions (bit 28) are supported in the
    // processor
    if (!(ecx & (1 << 28)))
        return false;
    else
        return true;
}

static void _set_xfrm(uint64_t xfrm)
{
    if (((xfrm & SGX_XFRM_AVX) == SGX_XFRM_AVX) && (!_is_avx_supported()))
        OE_TRACE_INFO("Skipping testing enclave in AVX mode as unsupported by "
                      "platform\n");
    else
        cur_enclave_xfrm = xfrm;
}

/*
 * Overriding oe_get_xfrm() function in the core to facilitate iterating through
 * Legacy and AVX configurations
 */
uint64_t oe_get_xfrm()
{
    return cur_enclave_xfrm;
}

static void _check_properties(
    oe_sgx_enclave_properties_t* props,
    bool is_signed,
    uint16_t product_id,
    uint16_t security_version,
    uint64_t attributes,
    uint64_t num_heap_pages,
    uint64_t num_stack_pages,
    uint64_t num_tcs)
{
    const oe_enclave_properties_header_t* header = &props->header;
    const oe_sgx_enclave_config_t* config = &props->config;

    /* Check the header */
    OE_TEST(header->size == sizeof(oe_sgx_enclave_properties_t));
    OE_TEST(header->enclave_type == OE_ENCLAVE_TYPE_SGX);
    OE_TEST(header->size_settings.num_heap_pages == num_heap_pages);
    OE_TEST(header->size_settings.num_stack_pages == num_stack_pages);
    OE_TEST(header->size_settings.num_tcs == num_tcs);

    /* Check the SGX config */
    OE_TEST(config->product_id == product_id);
    OE_TEST(config->security_version == security_version);
    OE_TEST(config->padding == 0);
    OE_TEST(config->attributes == attributes);
    OE_TEST(config->xfrm == cur_enclave_xfrm);

    /* Initialize a zero-filled sigstruct */
    const uint8_t sigstruct[OE_SGX_SIGSTRUCT_SIZE] = {0};

    /* Check for presence or absence of the signature */
    if (is_signed)
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) != 0);
    else
        OE_TEST(memcmp(props->sigstruct, sigstruct, sizeof(sigstruct)) == 0);
}

static oe_result_t _sgx_load_enclave_properties(
    const char* path,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_image_t oeimage = {0};

    if (properties)
        memset(properties, 0, sizeof(oe_sgx_enclave_properties_t));

    /* Check parameters */
    if (!path || !properties)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the ELF image */
    if (oe_load_enclave_image(path, &oeimage) != 0)
        OE_RAISE(OE_FAILURE);

    /* Load the SGX enclave properties */
    if (oe_sgx_load_enclave_properties(
            &oeimage, OE_INFO_SECTION_NAME, properties) != OE_OK)
        OE_RAISE(OE_NOT_FOUND);

    /* Since XFRM isn't stored in the image, set it here */
    properties->config.xfrm = oe_get_xfrm();

    result = OE_OK;

done:

    if (oeimage.elf.elf.magic == ELF_MAGIC)
        oe_unload_enclave_image(&oeimage);

    return result;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    bool is_signed = false;
    oe_sgx_enclave_properties_t properties;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Extract "signed" or "unsigned" command-line argument */
    if (strcmp(argv[2], "signed") == 0)
    {
        is_signed = true;
        _set_xfrm(SGX_XFRM_LEGACY);
    }
    else if (strcmp(argv[2], "unsigned") == 0)
    {
        is_signed = false;
        _set_xfrm(SGX_XFRM_LEGACY | SGX_XFRM_AVX);
    }
    else
    {
        fprintf(stderr, "%s: invalid argument: %s\n", argv[0], argv[2]);
        exit(1);
    }

    /* Load the enclave properties */
    if ((result = _sgx_load_enclave_properties(argv[1], &properties)) != OE_OK)
    {
        oe_put_err("oe_sgx_load_enclave_properties(): result=%u", result);
    }

    const uint32_t flags = oe_get_create_flags();
    result = oe_create_props_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    /* Check expected enclave property values */
    if (is_signed)
    {
        _check_properties(
            &properties,
            is_signed,
            1111,                                        /* product_id */
            2222,                                        /* security_version */
            OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT, /* attributes */
            512,                                         /* num_heap_pages  */
            512,                                         /* num_stack_pages */
            4);                                          /* num_tcs */
    }
    else
    {
        _check_properties(
            &properties,
            is_signed,
            1234,                                        /* product_id */
            5678,                                        /* security_version */
            OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT, /* attributes */
            512,                                         /* num_heap_pages  */
            512,                                         /* num_stack_pages */
            4);                                          /* num_tcs */
    }

    int out_param = -1;
    int return_val;

    result = enc_props(enclave, &return_val, &out_param);

    if (OE_OK != result)
        oe_put_err("call enclave failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    if (out_param != 0)
        oe_put_err("ECALL failed out_param=%d", out_param);

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (props)\n");

    return 0;
}
