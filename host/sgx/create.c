// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../strings.h"

#if defined(__linux__)
#include <errno.h>
#include <sys/mman.h>

#define get_fullpath(path) realpath(path, NULL)

#elif defined(_WIN32)
#include <windows.h>
#include "windows/exception.h"

static char* get_fullpath(const char* path)
{
    char* fullpath = (char*)calloc(1, MAX_PATH);
    if (fullpath)
    {
        DWORD length = GetFullPathName(path, MAX_PATH, fullpath, NULL);

        // If function failed, deallocate and return zero.
        if (length == 0)
        {
            free(fullpath);
            fullpath = NULL;
        }
    }
    return fullpath;
}

#endif

#include <assert.h>
#include <openenclave/bits/defs.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/result.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/switchless.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <string.h>
#include "../memalign.h"
#include "cpuid.h"
#include "enclave.h"
#include "exception.h"
#include "platform_u.h"
#include "sgxload.h"

#if !defined(OEHOSTMR)
static oe_once_type _enclave_init_once;

static void _initialize_exception_handling(void)
{
    oe_initialize_host_exception();
}

/*
**==============================================================================
**
** The per process enclave host side initialization.
**
**==============================================================================
*/

static void _initialize_enclave_host()
{
    oe_once(&_enclave_init_once, _initialize_exception_handling);

#ifdef OE_USE_BUILTIN_EDL
    oe_register_core_ocall_function_table();
    oe_register_platform_ocall_function_table();
    oe_register_syscall_ocall_function_table();
#endif // OE_USE_BUILTIN_EDL
}
#endif // OEHOSTMR

static oe_result_t _add_filled_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages,
    uint32_t filler,
    bool extend)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_page_t* page = NULL;
    size_t i;

    page = oe_memalign(OE_PAGE_SIZE, sizeof(oe_page_t));
    if (!page)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Reject invalid parameters */
    if (!context || !enclave_addr || !vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Fill or clear the page */
    if (filler)
    {
        size_t n = OE_PAGE_SIZE / sizeof(uint32_t);
        uint32_t* p = (uint32_t*)page;

        while (n--)
            *p++ = filler;
    }
    else
        memset(page, 0, sizeof(*page));

    /* Add the pages */
    for (i = 0; i < npages; i++)
    {
        uint64_t addr = enclave_addr + *vaddr;
        uint64_t src = (uint64_t)page;
        uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;

        OE_CHECK(oe_sgx_load_enclave_data(
            context, enclave_addr, addr, src, flags, extend));
        (*vaddr) += OE_PAGE_SIZE;
    }

    result = OE_OK;

done:
    if (page)
        oe_memalign_free(page);

    return result;
}

static oe_result_t _add_stack_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages)
{
    const bool extend = true;
    return _add_filled_pages(
        context, enclave_addr, vaddr, npages, 0xcccccccc, extend);
}

static oe_result_t _add_heap_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr,
    size_t npages)
{
    /* Do not measure heap pages */
    const bool extend = false;
    return _add_filled_pages(context, enclave_addr, vaddr, npages, 0, extend);
}

static oe_result_t _add_control_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t enclave_size,
    uint64_t entry,
    uint64_t* vaddr,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_page_t* page = NULL;

    if (!context || !enclave_addr || !enclave_size || !entry || !vaddr ||
        !enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create four "control" pages:
     *     page1 - page containing thread control structure (TCS)
     *     page2 - state-save-area (SSA) slot (zero-filled)
     *     page3 - state-save-area (SSA) slot (zero-filled)
     *     page4 - guard page
     *     page5 - thread local storage page.
     *     page6 - extra segment space for thread-specific data.
     */

    /* Save the address of new TCS page into enclave object */
    {
        if (enclave->num_bindings == OE_SGX_MAX_TCS)
            OE_RAISE_MSG(
                OE_FAILURE, "OE_SGX_MAX_TCS (%d) hit\n", OE_SGX_MAX_TCS);

        enclave->bindings[enclave->num_bindings].enclave = enclave;
        enclave->bindings[enclave->num_bindings++].tcs = enclave_addr + *vaddr;
    }

    /* Add the TCS page */
    {
        sgx_tcs_t* tcs;
        page = oe_memalign(OE_PAGE_SIZE, sizeof(oe_page_t));
        if (!page)
            OE_RAISE(OE_OUT_OF_MEMORY);

        /* Zero-fill the TCS page */
        memset(page, 0, sizeof(*page));

        /* Set TCS to pointer to page */
        tcs = (sgx_tcs_t*)page;

        /* No flags for now */
        tcs->flags = 0;

        /* SSA resides on page immediately following the TCS page */
        tcs->ossa = *vaddr + OE_PAGE_SIZE;

        /* Used at runtime (set to zero for now) */
        tcs->cssa = 0;

        /* Reserve two slots (both which follow the TCS page) */
        tcs->nssa = 2;

        /* The entry point for the program (from ELF) */
        tcs->oentry = entry;

        /* FS segment: Used for thread-local variables.
         * The reserved (unused) space in oe_sgx_td_t is used for thread-local
         * variables.
         * Since negative offsets are used with FS, FS must point to end of the
         * segment.
         */
        tcs->fsbase = *vaddr + (5 * OE_PAGE_SIZE);

        /* The existing Windows SGX enclave debugger finds the start of the
         * thread data by assuming that it is located at the start of the GS
         * segment. i.e. it adds the enclave base address and the offset to the
         * GS segment stored in TCS.OGSBASGX.  OE SDK uses the FS segment for
         * this purpose and has no separate use for the GS register, so we
         * point it at the FS segment to preserve the Windows debugger
         * behavior.
         */
        tcs->gsbase = tcs->fsbase;

        /* Set to maximum value */
        tcs->fslimit = 0xFFFFFFFF;

        /* Set to maximum value */
        tcs->gslimit = 0xFFFFFFFF;

        /* Ask ISGX driver perform EADD on this page */
        {
            uint64_t addr = enclave_addr + *vaddr;
            uint64_t src = (uint64_t)page;
            uint64_t flags = SGX_SECINFO_TCS;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave_addr, addr, src, flags, extend));
        }

        /* Increment the page size */
        (*vaddr) += OE_PAGE_SIZE;
    }

    /* Add two blank pages */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 2, 0, true));

    /* Skip over guard page */
    (*vaddr) += OE_PAGE_SIZE;

    /* Add one blank pages (for either FS segment or GS segment) */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 1, 0, true));

    /* Add one page for thread-specific data (TSD) slots */
    OE_CHECK(_add_filled_pages(context, enclave_addr, vaddr, 1, 0, true));

    result = OE_OK;

done:
    if (page)
        oe_memalign_free(page);

    return result;
}

static oe_result_t _calculate_enclave_size(
    size_t image_size,
    const oe_sgx_enclave_properties_t* props,
    size_t* enclave_end, /* end may be less than size due to rounding */
    size_t* enclave_size)

{
    oe_result_t result = OE_UNEXPECTED;
    size_t heap_size;
    size_t stack_size;
    size_t control_size;
    const oe_enclave_size_settings_t* size_settings;

    size_settings = &props->header.size_settings;

    *enclave_size = 0;
    *enclave_end = 0;

    /* Compute size in bytes of the heap */
    heap_size = size_settings->num_heap_pages * OE_PAGE_SIZE;

    /* Compute size of the stack (one per TCS; include guard pages) */
    stack_size = OE_PAGE_SIZE // guard page
                 + (size_settings->num_stack_pages * OE_PAGE_SIZE) +
                 OE_PAGE_SIZE; // guard page

    /* Compute the control size in bytes (6 pages total) */
    control_size = 6 * OE_PAGE_SIZE;

    /* Compute end of the enclave */
    *enclave_end = image_size + heap_size +
                   (size_settings->num_tcs * (stack_size + control_size));

    /* Calculate the total size of the enclave */
    *enclave_size = oe_round_u64_to_pow2(*enclave_end);

    result = OE_OK;
    return result;
}

static oe_result_t _add_data_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    const oe_sgx_enclave_properties_t* props,
    uint64_t entry,
    uint64_t* vaddr)

{
    oe_result_t result = OE_UNEXPECTED;
    const oe_enclave_size_settings_t* size_settings =
        &props->header.size_settings;
    size_t i;

    /* Add the heap pages */
    OE_CHECK(_add_heap_pages(
        context, enclave->addr, vaddr, size_settings->num_heap_pages));

    for (i = 0; i < size_settings->num_tcs; i++)
    {
        /* Add guard page */
        *vaddr += OE_PAGE_SIZE;

        /* Add the stack for this thread control structure */
        OE_CHECK(_add_stack_pages(
            context, enclave->addr, vaddr, size_settings->num_stack_pages));

        /* Add guard page */
        *vaddr += OE_PAGE_SIZE;

        /* Add the "control" pages */
        OE_CHECK(_add_control_pages(
            context, enclave->addr, enclave->size, entry, vaddr, enclave));
    }

    result = OE_OK;

done:
    return result;
}

#if !defined(OEHOSTMR)
oe_result_t oe_sgx_get_cpuid_table_ocall(
    void* cpuid_table_buffer,
    size_t cpuid_table_buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    unsigned int subleaf = 0; // pass sub-leaf of 0 - needed for leaf 4
    uint32_t* leaf;
    size_t size;

    leaf = (uint32_t*)cpuid_table_buffer;
    size = sizeof(uint32_t) * OE_CPUID_LEAF_COUNT * OE_CPUID_REG_COUNT;

    if (!cpuid_table_buffer || cpuid_table_buffer_size != size)
        OE_RAISE(OE_INVALID_PARAMETER);

    for (unsigned int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        oe_get_cpuid(
            i,
            subleaf,
            &leaf[OE_CPUID_RAX],
            &leaf[OE_CPUID_RBX],
            &leaf[OE_CPUID_RCX],
            &leaf[OE_CPUID_RDX]);

        leaf += OE_CPUID_REG_COUNT;
    }

    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** _initialize_enclave()
**
**     Invokes first oe_ecall into the enclave to trigger rebase and set up
**     enclave runtime global state, such as CPUID information from host.
**
**==============================================================================
*/

static oe_result_t _initialize_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t result_out = 0;

    OE_CHECK(oe_ecall(
        enclave, OE_ECALL_INIT_ENCLAVE, (uint64_t)enclave, &result_out));

    if (result_out > OE_UINT32_MAX)
        OE_RAISE(OE_FAILURE);

    if (!oe_is_valid_result((uint32_t)result_out))
        OE_RAISE(OE_FAILURE);

    OE_CHECK((oe_result_t)result_out);

    result = OE_OK;

done:
    return result;
}

/*
** _config_enclave()
**
** Config the enclave with an array of settings.
*/

static oe_result_t _configure_enclave(
    oe_enclave_t* enclave,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count)
{
    oe_result_t result = OE_UNEXPECTED;

    for (uint32_t i = 0; i < setting_count; i++)
    {
        switch (settings[i].setting_type)
        {
            // Configure the switchless ocalls, such as the number of workers.
            case OE_ENCLAVE_SETTING_CONTEXT_SWITCHLESS:
            {
                size_t max_host_workers =
                    settings[i].u.context_switchless_setting->max_host_workers;
                size_t max_enclave_workers =
                    settings[i]
                        .u.context_switchless_setting->max_enclave_workers;

                OE_CHECK(oe_start_switchless_manager(
                    enclave, max_host_workers, max_enclave_workers));
                break;
            }
            default:
                OE_RAISE(OE_INVALID_PARAMETER);
        }
    }
    result = OE_OK;

done:
    return result;
}
#endif // OEHOSTMR

oe_result_t oe_sgx_validate_enclave_properties(
    const oe_sgx_enclave_properties_t* properties,
    const char** field_name)
{
    oe_result_t result = OE_UNEXPECTED;

    if (field_name)
        *field_name = NULL;

    /* Check for null parameters */
    if (!properties)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!oe_sgx_is_valid_attributes(properties->config.attributes))
    {
        if (field_name)
            *field_name = "config.attributes";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_attributes failed: attributes = %lx\n",
            properties->config.attributes);
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_heap_pages(
            properties->header.size_settings.num_heap_pages))
    {
        if (field_name)
            *field_name = "header.size_settings.num_heap_pages";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_num_heap_pages failed: num_heap_pages = %lx\n",
            properties->header.size_settings.num_heap_pages);
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_stack_pages(
            properties->header.size_settings.num_stack_pages))
    {
        if (field_name)
            *field_name = "header.size_settings.num_stack_pages";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_num_stack_pages failed: "
            "num_heap_pnum_stack_pagesages = %lx\n",
            properties->header.size_settings.num_stack_pages);
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_num_tcs(properties->header.size_settings.num_tcs))
    {
        if (field_name)
            *field_name = "header.size_settings.num_tcs";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_num_tcs failed: num_tcs = %lx\n",
            properties->header.size_settings.num_tcs);
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_product_id(properties->config.product_id))
    {
        if (field_name)
            *field_name = "config.product_id";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_product_id failed: product_id = %x\n",
            properties->config.product_id);
        result = OE_FAILURE;
        goto done;
    }

    if (!oe_sgx_is_valid_security_version(properties->config.security_version))
    {
        if (field_name)
            *field_name = "config.security_version";
        OE_TRACE_ERROR(
            "oe_sgx_is_valid_security_version failed: security_version = %x\n",
            properties->config.security_version);
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_sgx_build_enclave(
    oe_sgx_load_context_t* context,
    const char* path,
    const oe_sgx_enclave_properties_t* properties,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t enclave_end = 0;
    size_t enclave_size = 0;
    uint64_t enclave_addr = 0;
    oe_enclave_image_t oeimage;
    void* ecall_data = NULL;
    size_t image_size;
    uint64_t vaddr = 0;
    oe_sgx_enclave_properties_t props;

    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    memset(&oeimage, 0, sizeof(oeimage));

    /* Clear and initialize enclave structure */
    {
        if (enclave)
            memset(enclave, 0, sizeof(oe_enclave_t));

        enclave->debug = oe_sgx_is_debug_load_context(context);
        enclave->simulate = oe_sgx_is_simulation_load_context(context);
    }

    /* Initialize the lock */
    if (oe_mutex_init(&enclave->lock))
        OE_RAISE(OE_FAILURE);

    /* Reject invalid parameters */
    if (!context || !path || !enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Load the elf object */
    if (oe_load_enclave_image(path, &oeimage) != OE_OK)
        OE_RAISE(OE_FAILURE);

    // If the **properties** parameter is non-null, use those properties.
    // Else use the properties stored in the .oeinfo section.
    if (properties)
    {
        props = *properties;

        /* Update image to the properties passed in */
        memcpy(oeimage.image_base + oeimage.oeinfo_rva, &props, sizeof(props));
    }
    else
    {
        /* Copy the properties from the image */
        memcpy(&props, oeimage.image_base + oeimage.oeinfo_rva, sizeof(props));
    }

    /* Validate the enclave prop_override structure */
    OE_CHECK(oe_sgx_validate_enclave_properties(&props, NULL));

    /* Consolidate enclave-debug-flag with create-debug-flag */
    if (props.config.attributes & OE_SGX_FLAGS_DEBUG)
    {
        if (!enclave->debug)
        {
            /* Upgrade to non-debug mode */
            props.config.attributes &= ~OE_SGX_FLAGS_DEBUG;
        }
    }
    else
    {
        if (enclave->debug)
        {
            /* Attempted to downgrade to debug mode */
            OE_RAISE_MSG(
                OE_DEBUG_DOWNGRADE,
                "Enclave image was signed without debug flag but is being "
                "loaded with OE_ENCLAVE_FLAG_DEBUG set in oe_create_enclave "
                "call\n",
                NULL);
        }
    }
    // Set the XFRM field
    props.config.xfrm = context->attributes.xfrm;

    /* Calculate the size of image */
    OE_CHECK(oeimage.calculate_size(&oeimage, &image_size));

    /* Calculate the size of this enclave in memory */
    OE_CHECK(_calculate_enclave_size(
        image_size, &props, &enclave_end, &enclave_size));

    /* Perform the ECREATE operation */
    OE_CHECK(oe_sgx_create_enclave(context, enclave_size, &enclave_addr));

    /* Save the enclave base address, size, and text address */
    enclave->addr = enclave_addr;
    enclave->size = enclave_size;
    enclave->text = enclave_addr + oeimage.text_rva;

    /* Patch image */
    OE_CHECK(oeimage.patch(&oeimage, enclave_end));

    /* Add image to enclave */
    OE_CHECK(oeimage.add_pages(&oeimage, context, enclave, &vaddr));

    /* Add data pages */
    OE_CHECK(
        _add_data_pages(context, enclave, &props, oeimage.entry_rva, &vaddr));

    /* Ask the platform to initialize the enclave and finalize the hash */
    OE_CHECK(oe_sgx_initialize_enclave(
        context, enclave_addr, &props, &enclave->hash));

    /* Save full path of this enclave. When a debugger attaches to the host
     * process, it needs the fullpath so that it can load the image binary and
     * extract the debugging symbols. */
    if (!(enclave->path = get_fullpath(path)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Set the magic number only if we have actually created an enclave */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE)
        enclave->magic = ENCLAVE_MAGIC;

    result = OE_OK;

done:

    if (ecall_data)
        free(ecall_data);

    oe_unload_enclave_image(&oeimage);

    return result;
}

#if !defined(OEHOSTMR)
/*
** This method encapsulates all steps of the enclave creation process:
**     - Loads an enclave image file
**     - Lays out the enclave memory image and injects enclave metadata
**     - Asks the platform to create the enclave (ECREATE)
**     - Asks the platform to add the pages to the EPC (EADD/EEXTEND)
**     - Asks the platform to initialize the enclave (EINIT)
**
** When built against the legacy Intel(R) SGX driver and Intel(R) AESM service
** dependencies, this method also:
**     - Maps the enclave memory image onto the driver device (/dev/isgx) for
**        ECREATE.
**     - Obtains a launch token (EINITKEY) from the Intel(R) launch enclave (LE)
**        for EINIT.
*/
oe_result_t oe_create_enclave(
    const char* enclave_path,
    oe_enclave_type_t enclave_type,
    uint32_t flags,
    const oe_enclave_setting_t* settings,
    uint32_t setting_count,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_count,
    oe_enclave_t** enclave_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_enclave_t* enclave = NULL;
    oe_sgx_load_context_t context;

    _initialize_enclave_host();

#if _WIN32
    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
    {
        oe_prepend_simulation_mode_exception_handler();
    }
#endif

    if (enclave_out)
        *enclave_out = NULL;

    /* Check parameters */
    if (!enclave_path || !enclave_out ||
        ((enclave_type != OE_ENCLAVE_TYPE_SGX) &&
         (enclave_type != OE_ENCLAVE_TYPE_AUTO)) ||
        (setting_count > 0 && settings == NULL) ||
        (setting_count == 0 && settings != NULL) ||
        (flags & OE_ENCLAVE_FLAG_RESERVED))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate and zero-fill the enclave structure */
    if (!(enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t))))
        OE_RAISE(OE_OUT_OF_MEMORY);

#if defined(_WIN32)
    /* Create Windows events for each TCS binding. Enclaves use
     * this event when calling into the host to handle waits/wakes
     * as part of the enclave mutex and condition variable
     * implementation.
     */
    for (size_t i = 0; i < enclave->num_bindings; i++)
    {
        oe_thread_binding_t* binding = &enclave->bindings[i];

        if (!(binding->event.handle = CreateEvent(
                  0,     /* No security attributes */
                  FALSE, /* Event is reset automatically */
                  FALSE, /* Event is not put in a signaled state
                            upon creation */
                  0)))   /* No name */
        {
            OE_RAISE_MSG(OE_FAILURE, "CreateEvent failed", NULL);
        }
    }

#endif

    /* Initialize the context parameter and any driver handles */
    OE_CHECK(oe_sgx_initialize_load_context(
        &context, OE_SGX_LOAD_TYPE_CREATE, flags));

    /* Build the enclave */
    OE_CHECK(oe_sgx_build_enclave(&context, enclave_path, NULL, enclave));

    /* Push the new created enclave to the global list. */
    if (oe_push_enclave_instance(enclave) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    // Create debugging structures only for debug enclaves.
    if (enclave->debug)
    {
        oe_debug_enclave_t* debug_enclave =
            (oe_debug_enclave_t*)calloc(1, sizeof(*debug_enclave));

        debug_enclave->magic = OE_DEBUG_ENCLAVE_MAGIC;
        debug_enclave->version = OE_DEBUG_ENCLAVE_VERSION;
        debug_enclave->next = NULL;

        debug_enclave->path = enclave->path;
        debug_enclave->path_length = strlen(enclave->path);

        debug_enclave->base_address = (void*)enclave->addr;
        debug_enclave->size = enclave->size;

        debug_enclave->tcs_array =
            (sgx_tcs_t**)calloc(enclave->num_bindings, sizeof(sgx_tcs_t*));
        for (uint64_t i = 0; i < enclave->num_bindings; ++i)
        {
            debug_enclave->tcs_array[i] = (sgx_tcs_t*)enclave->bindings[i].tcs;
        }
        debug_enclave->num_tcs = enclave->num_bindings;

        debug_enclave->flags = 0;
        if (enclave->debug)
            debug_enclave->flags |= OE_DEBUG_ENCLAVE_MASK_DEBUG;
        if (enclave->simulate)
            debug_enclave->flags |= OE_DEBUG_ENCLAVE_MASK_SIMULATE;

        enclave->debug_enclave = debug_enclave;
        oe_debug_notify_enclave_created(debug_enclave);
    }

    /* Enclave initialization invokes global constructors which could make
     * ocalls. Therefore setup ocall table prior to initialization. */
    enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
    enclave->num_ocalls = ocall_count;

    /* Invoke enclave initialization. */
    OE_CHECK(_initialize_enclave(enclave));

    /* Apply the list of settings to the enclave */
    OE_CHECK(_configure_enclave(enclave, settings, setting_count));

    /* Setup logging configuration */
    oe_log_enclave_init(enclave);

    *enclave_out = enclave;
    result = OE_OK;

done:

    if (result != OE_OK && enclave)
    {
        free(enclave);
    }

    oe_sgx_cleanup_load_context(&context);

    return result;
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Check parameters */
    if (!enclave || enclave->magic != ENCLAVE_MAGIC)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Shut down the switchless manager */
    OE_CHECK(oe_stop_switchless_manager(enclave));

    /* Call the enclave destructor */
    OE_CHECK(oe_ecall(enclave, OE_ECALL_DESTRUCTOR, 0, NULL));

    if (enclave->debug_enclave)
    {
        oe_debug_notify_enclave_terminated(enclave->debug_enclave);
        free(enclave->debug_enclave->tcs_array);
        free(enclave->debug_enclave);
    }

    /* Once the enclave destructor has been invoked, the enclave memory
     * and data structures are freed on a best effort basis from here on */

    /* Remove this enclave from the global list. */
    oe_remove_enclave_instance(enclave);

    /* Clear the magic number */
    enclave->magic = 0;

    oe_mutex_lock(&enclave->lock);
    {
        /* Unmap the enclave memory region.
         * Track failures reported by the platform, but do not exit early */
        result = oe_sgx_delete_enclave(enclave);

#if defined(_WIN32)

        /* Release Windows events created during enclave creation */
        for (size_t i = 0; i < enclave->num_bindings; i++)
        {
            oe_thread_binding_t* binding = &enclave->bindings[i];
            CloseHandle(binding->event.handle);
            free(binding->ocall_buffer);
        }

#endif

        /* Free the path name of the enclave image file */
        free(enclave->path);
    }
    /* Release and destroy the mutex object */
    oe_mutex_unlock(&enclave->lock);
    oe_mutex_destroy(&enclave->lock);

    /* Clear the contents of the enclave structure */

    memset(enclave, 0, sizeof(oe_enclave_t));

    /* Free the enclave structure */
    free(enclave);

done:
    return result;
}
#endif // OEHOSTMR
