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
#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/load.h>
#include <openenclave/internal/mem.h>
#include <openenclave/internal/properties.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/result.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgx/extradata.h>
#include <openenclave/internal/sgxcreate.h>
#include <openenclave/internal/sgxsign.h>
#include <openenclave/internal/switchless.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include <string.h>
#include "../memalign.h"
#include "../signkey.h"
#include "cpuid.h"
#include "enclave.h"
#include "exception.h"
#include "platform_u.h"
#include "sgxload.h"
#include "vdso.h"
#include "xstate.h"

static volatile oe_load_extra_enclave_data_hook_t
    _oe_load_extra_enclave_data_hook;

#if !defined(OEHOSTMR)
static oe_once_type _enclave_init_once;

/* Global for caching the result of AVX check used by oe_enter */
bool oe_is_avx_enabled = false;

/* Global that indicates if SGX vDSO is enabled, which is used
 * by oe_enter, oe_host_handle_exception, and _register_signal_handlers */
bool oe_sgx_is_vdso_enabled = false;

/* Forward declaration */
void oe_sgx_host_enable_debug_pf_simulation(void);

static void _initialize_enclave_host_impl(void)
{
    uint64_t xfrm = oe_get_xfrm();
    oe_is_avx_enabled = ((xfrm & SGX_XFRM_AVX) == SGX_XFRM_AVX) ||
                        ((xfrm & SGX_XFRM_AVX512) == SGX_XFRM_AVX512);

    if (oe_sgx_initialize_vdso() == OE_OK)
        oe_sgx_is_vdso_enabled = true;

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
    oe_once(&_enclave_init_once, _initialize_enclave_host_impl);
}
#endif // OEHOSTMR

bool oe_sgx_is_kss_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(CPUID_SGX_LEAF, 0x1, &eax, &ebx, &ecx, &edx);

    // Check if KSS (bit 7) is supported by the processor
    return (eax & CPUID_SGX_KSS_MASK);
}

bool oe_sgx_is_misc_region_supported(void)
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(CPUID_SGX_LEAF, 0x0, &eax, &ebx, &ecx, &edx);

    // Check if EXINFO is supported by the processor
    return (ebx & CPUID_SGX_MISC_EXINFO_MASK);
}

static oe_result_t _add_filled_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
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
    if (!context || !enclave || !vaddr || !enclave->start_address)
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
        uint64_t addr = enclave->start_address + *vaddr;
        uint64_t src = (uint64_t)page;
        uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;

        OE_CHECK(oe_sgx_load_enclave_data(
            context, enclave->base_address, addr, src, flags, extend));
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
    oe_enclave_t* enclave,
    uint64_t* vaddr,
    size_t npages)
{
    const bool extend = true;
    return _add_filled_pages(
        context, enclave, vaddr, npages, 0xcccccccc, extend);
}

static oe_result_t _add_heap_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    uint64_t* vaddr,
    size_t npages)
{
    /* Do not measure heap pages */
    const bool extend = false;
    return _add_filled_pages(context, enclave, vaddr, npages, 0, extend);
}

static oe_result_t _add_control_pages(
    oe_sgx_load_context_t* context,
    uint64_t entry,
    size_t tls_page_count,
    uint64_t* vaddr,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_page_t* page = NULL;

    if (!context || !entry || !vaddr || !enclave || !enclave->start_address ||
        !enclave->size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create "control" pages:
     *     page1 - page containing thread control structure (TCS)
     *     page2 - state-save-area (SSA) slot (zero-filled)
     *     page3 - state-save-area (SSA) slot (zero-filled)
     *     page4 - guard page
     *             thread local storage pages.
     *     pageN - extra segment space for thread-specific data.
     */

    /* Save the address of new TCS page into enclave object */
    {
        if (enclave->num_bindings == OE_SGX_MAX_TCS)
            OE_RAISE_MSG(
                OE_FAILURE, "OE_SGX_MAX_TCS (%d) hit\n", OE_SGX_MAX_TCS);

        enclave->bindings[enclave->num_bindings].enclave = enclave;
        enclave->bindings[enclave->num_bindings++].tcs =
            enclave->start_address + *vaddr;
    }

    /* Add the TCS page */
    {
        sgx_tcs_t* tcs;
        page = oe_memalign(OE_PAGE_SIZE, sizeof(oe_page_t));
        if (!page)
            OE_RAISE(OE_OUT_OF_MEMORY);

        /* Zero-fill the TCS page */
        memset(page, 0, sizeof(*page));

        /*
         * Addresses in TCS are expected to be relative to the base address
         * of the enclave, while vaddr is relative to address zero.
         * Add base_offset to adjust these addresses.
         */
        uint64_t base_offset = enclave->start_address - enclave->base_address;

        /* Set TCS to pointer to page */
        tcs = (sgx_tcs_t*)page;

        /* No flags for now */
        tcs->flags = 0;

        /* SSA resides on page immediately following the TCS page */
        tcs->ossa = base_offset + *vaddr + OE_PAGE_SIZE;

        /* Used at runtime (set to zero for now) */
        tcs->cssa = 0;

        /* Reserve two slots (both which follow the TCS page) */
        tcs->nssa = 2;

        /* The entry point for the program (from ELF) */
        tcs->oentry = base_offset + entry;

        /* FS segment: Used for thread-local variables.
         * The reserved (unused) space in oe_sgx_td_t is used for thread-local
         * variables.
         * Since negative offsets are used with FS, FS must point to end of the
         * segment.
         */
        tcs->fsbase =
            base_offset + *vaddr +
            (tls_page_count + OE_SGX_TCS_CONTROL_PAGES) * OE_PAGE_SIZE;

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
            uint64_t addr = enclave->start_address + *vaddr;
            uint64_t src = (uint64_t)page;
            uint64_t flags = SGX_SECINFO_TCS;
            bool extend = true;

            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave->base_address, addr, src, flags, extend));
        }

        /* Increment the page size */
        (*vaddr) += OE_PAGE_SIZE;
    }

    /* Add two blank pages */
    OE_CHECK(_add_filled_pages(context, enclave, vaddr, 2, 0, true));

    /* Skip over guard page */
    (*vaddr) += OE_PAGE_SIZE;

    /* Add blank pages (for either FS segment or GS segment) */
    if (tls_page_count)
        OE_CHECK(_add_filled_pages(
            context, enclave, vaddr, tls_page_count, 0, true));

    /* Add one page for thread-specific data (TSD) slots */
    OE_CHECK(_add_filled_pages(context, enclave, vaddr, 1, 0, true));

    result = OE_OK;

done:
    if (page)
        oe_memalign_free(page);

    return result;
}

void oe_register_load_extra_enclave_data_hook(
    oe_load_extra_enclave_data_hook_t hook)
{
    _oe_load_extra_enclave_data_hook = hook;
}

oe_result_t oe_load_extra_enclave_data(
    oe_load_extra_enclave_data_hook_arg_t* arg,
    uint64_t vaddr,
    const void* page,
    uint64_t flags,
    bool extend)
{
    oe_result_t result = OE_OK;

    if (!arg || arg->magic != OE_LOAD_EXTRA_ENCLAVE_DATA_HOOK_ARG_MAGIC)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!page)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (vaddr < arg->vaddr)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (arg->sgx_load_context)
    {
        uint64_t addr = arg->enclave_start + arg->base_vaddr + vaddr;

        OE_CHECK(oe_sgx_load_enclave_data(
            arg->sgx_load_context,
            arg->enclave_base,
            addr,
            (uint64_t)page,
            flags,
            extend));
    }

    arg->vaddr = vaddr + OE_PAGE_SIZE;

done:
    return result;
}

static oe_result_t _calculate_enclave_size(
    size_t image_size,
    size_t tls_page_count,
    const oe_sgx_enclave_properties_t* props,
    size_t* loaded_enclave_pages_size,
    size_t* enclave_size,
    size_t* extra_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t heap_size;
    size_t stack_size;
    size_t tls_size;
    size_t control_size;
    const oe_enclave_size_settings_t* size_settings;

    size_settings = &props->header.size_settings;

    if (enclave_size)
        *enclave_size = 0;

    if (extra_data_size)
        *extra_data_size = 0;

    /* Calculate the total size of the extra enclave data (if any).
     * The hook implementation is expected to invoke oe_load_extra_enclave_data
     * on each data page, which will output the total size of extra data in the
     * vaddr argument. */
    if (_oe_load_extra_enclave_data_hook && extra_data_size)
    {
        oe_load_extra_enclave_data_hook_arg_t arg = {
            .magic = OE_LOAD_EXTRA_ENCLAVE_DATA_HOOK_ARG_MAGIC,
            .sgx_load_context = NULL,
            .enclave_base = 0,
            .enclave_start = 0,
            .base_vaddr = 0,
            .vaddr = 0,
        };
        OE_CHECK(_oe_load_extra_enclave_data_hook(&arg, 0));
        *extra_data_size = arg.vaddr;
    }

    *loaded_enclave_pages_size = 0;

    /* Compute size in bytes of the heap */
    heap_size = size_settings->num_heap_pages * OE_PAGE_SIZE;

    /* Compute size of the stack (one per TCS; include guard pages) */
    stack_size = OE_PAGE_SIZE // guard page
                 + (size_settings->num_stack_pages * OE_PAGE_SIZE) +
                 OE_PAGE_SIZE; // guard page

    /* Compute size of the TLS */
    tls_size = tls_page_count * OE_PAGE_SIZE;

    /* Compute the control size in bytes (5 pages total) */
    control_size = (OE_SGX_TCS_CONTROL_PAGES + OE_SGX_TCS_THREAD_DATA_PAGES) *
                   OE_PAGE_SIZE;

    /* Compute end of the enclave */
    *loaded_enclave_pages_size =
        image_size + heap_size +
        (size_settings->num_tcs * (stack_size + tls_size + control_size));

    if (extra_data_size)
        *loaded_enclave_pages_size += *extra_data_size;

    if (enclave_size)
    {
#ifdef OE_WITH_EXPERIMENTAL_EEID
        if (is_eeid_base_image(props))
            *enclave_size = OE_EEID_SGX_ELRANGE;
        else
#endif
            /* Calculate the total size of the enclave */
            *enclave_size = oe_round_u64_to_pow2(*loaded_enclave_pages_size);
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _add_data_pages(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    const oe_sgx_enclave_properties_t* props,
    uint64_t entry,
    size_t tls_page_count,
    uint64_t* vaddr)

{
    oe_result_t result = OE_UNEXPECTED;
    const oe_enclave_size_settings_t* size_settings =
        &props->header.size_settings;
    size_t i;

    /* Add the heap pages */
    OE_CHECK(_add_heap_pages(
        context, enclave, vaddr, size_settings->num_heap_pages));

    for (i = 0; i < size_settings->num_tcs; i++)
    {
        /* Add guard page */
        *vaddr += OE_PAGE_SIZE;

        /* Add the stack for this thread control structure */
        OE_CHECK(_add_stack_pages(
            context, enclave, vaddr, size_settings->num_stack_pages));

        /* Add guard page */
        *vaddr += OE_PAGE_SIZE;

        /* Add the "control" pages */
        OE_CHECK(
            _add_control_pages(context, entry, tls_page_count, vaddr, enclave));
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
            supported_cpuid_leaves[i],
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

    OE_TRACE_INFO("Invoking the initialization ECALL");

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
            case OE_SGX_ENCLAVE_CONFIG_DATA:
            {
                break;
            }
#ifdef OE_WITH_EXPERIMENTAL_EEID
            case OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA:
            {
                // Nothing
                break;
            }
#endif
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

    if (properties->config.flags.create_zero_base_enclave)
    {
        if (!oe_sgx_is_valid_start_address(properties->config.start_address))
        {
            if (field_name)
                *field_name = "config.start_address";
            OE_TRACE_ERROR(
                "oe_sgx_is_valid_start_address failed: start_address = %lx\n",
                properties->config.start_address);
            result = OE_FAILURE;
            goto done;
        }
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

    if (!(properties->config.attributes & OE_SGX_FLAGS_KSS))
    {
        if (!oe_sgx_is_unset_uuid(
                (uint8_t*)properties->config.extended_product_id))
        {
            OE_TRACE_ERROR("oe_sgx_is_unset_uuid failed: extended_product_id "
                           "should be empty");
            result = OE_FAILURE;
            goto done;
        }
        if (!oe_sgx_is_unset_uuid((uint8_t*)properties->config.family_id))
        {
            OE_TRACE_ERROR(
                "oe_sgx_is_unset_uuid failed: family_id should be empty");
            result = OE_FAILURE;
            goto done;
        }
    }
    result = OE_OK;

done:
    return result;
}

#ifdef OE_WITH_EXPERIMENTAL_EEID
static oe_result_t _add_eeid_marker_page(
    oe_sgx_load_context_t* context,
    oe_enclave_t* enclave,
    size_t image_size,
    size_t tls_page_count,
    uint64_t entry_point,
    oe_sgx_enclave_properties_t* props,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_eeid_t* eeid = context->eeid;

    if (eeid && is_eeid_base_image(props) &&
        context->type == OE_SGX_LOAD_TYPE_CREATE)
    {
        // Finalize the memory settings
        props->header.size_settings = eeid->size_settings;

        // Record EEID information
        eeid->version = OE_EEID_VERSION;
        oe_sha256_context_t* hctx = &context->hash_context;
        oe_sha256_save(hctx, eeid->hash_state.H, eeid->hash_state.N);
        eeid->entry_point = entry_point;
        eeid->vaddr = *vaddr;
        eeid->tls_page_count = tls_page_count;
        eeid->signature_size = sizeof(sgx_sigstruct_t);
        memcpy(
            eeid->data + eeid->data_size,
            (uint8_t*)&props->sigstruct,
            sizeof(sgx_sigstruct_t));

        oe_page_t* page = oe_memalign(OE_PAGE_SIZE, sizeof(oe_page_t));
        memset(page, 0, sizeof(oe_page_t));
        oe_eeid_marker_t* marker = (oe_eeid_marker_t*)page;

        /* The offset to the EEID in marker->offset is also the extended
         * commit size of the base image and dynamically configured data
         * pages (stacks + heap) excluding the EEID data size.
         */
        _calculate_enclave_size(
            image_size, tls_page_count, props, &marker->offset, NULL, NULL);

        uint64_t addr = enclave->start_address + *vaddr;
        uint64_t src = (uint64_t)page;
        uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R | SGX_SECINFO_W;

        OE_CHECK(oe_sgx_load_enclave_data(
            context, enclave->start_address, addr, src, flags, false));
        (*vaddr) += OE_PAGE_SIZE;
        oe_memalign_free(page);

        // Marker page counts as a heap page
        if (props->header.size_settings.num_heap_pages > 0)
            props->header.size_settings.num_heap_pages--;
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _eeid_resign(
    oe_sgx_load_context_t* context,
    oe_sgx_enclave_properties_t* properties)
{
    oe_result_t result = OE_OK;
    oe_eeid_t* eeid = context->eeid;

    if (eeid && eeid->data_size > 0)
    {
        sgx_sigstruct_t* sigstruct = (sgx_sigstruct_t*)properties->sigstruct;

        OE_SHA256 ext_mrenclave;
        oe_sha256_final(&context->hash_context, &ext_mrenclave);

        OE_CHECK(oe_sgx_sign_enclave(
            &ext_mrenclave,
            properties->config.attributes,
            properties->config.product_id,
            properties->config.security_version,
            &properties->config.flags,
            OE_DEBUG_SIGN_KEY,
            OE_DEBUG_SIGN_KEY_SIZE,
            properties->config.family_id,
            properties->config.extended_product_id,
            sigstruct));
    }

done:
    return result;
}

static oe_result_t _add_eeid_pages(
    oe_sgx_load_context_t* context,
    uint64_t enclave_addr,
    uint64_t* vaddr)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_eeid_t* eeid = context->eeid;

    if (eeid)
    {
        char* eeid_bytes = (char*)eeid;
        size_t num_bytes = oe_eeid_byte_size(eeid);
        size_t num_pages =
            num_bytes / OE_PAGE_SIZE + ((num_bytes % OE_PAGE_SIZE) ? 1 : 0);

        oe_page_t* page = oe_memalign(OE_PAGE_SIZE, sizeof(oe_page_t));
        for (size_t i = 0; i < num_pages; i++)
        {
            memset(page->data, 0, sizeof(oe_page_t));
            size_t n = (i != num_pages - 1) ? OE_PAGE_SIZE
                                            : (num_bytes % OE_PAGE_SIZE);
            memcpy(page->data, eeid_bytes + OE_PAGE_SIZE * i, n);

            uint64_t addr = enclave_addr + *vaddr;
            uint64_t src = (uint64_t)(page->data);
            uint64_t flags = SGX_SECINFO_REG | SGX_SECINFO_R;
            OE_CHECK(oe_sgx_load_enclave_data(
                context, enclave_addr, addr, src, flags, true));
            *vaddr += OE_PAGE_SIZE;
        }
        oe_memalign_free(page);
    }

    result = OE_OK;

done:
    return result;
}
#endif

oe_result_t oe_sgx_build_enclave(
    oe_sgx_load_context_t* context,
    const char* path,
    const oe_sgx_enclave_properties_t* properties,
    oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t loaded_enclave_pages_size = 0;
    size_t enclave_size = 0;
    uint64_t enclave_addr = 0;
    oe_enclave_image_t oeimage;
    void* ecall_data = NULL;
    size_t image_size;
    size_t tls_page_count;
    uint64_t vaddr = 0;
    oe_sgx_enclave_properties_t props;
    size_t extra_data_size = 0;

    /* Reject invalid parameters */
    if (!context || !path || !enclave)
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

    /* Load the elf object */
    if (oe_load_enclave_image(path, &oeimage) != OE_OK)
        OE_RAISE(OE_FAILURE);

    // If the **properties** parameter is non-null, use those properties.
    // Else use the properties stored in the .oeinfo section.
    if (properties)
    {
        props = *properties;

        /* Update image to the properties passed in */
        memcpy(
            oeimage.elf.image_base + oeimage.elf.oeinfo_rva,
            &props,
            sizeof(props));
    }
    else
    {
        /* Copy the properties from the image */
        memcpy(
            &props,
            oeimage.elf.image_base + oeimage.elf.oeinfo_rva,
            sizeof(props));
    }

    /* Validate the enclave prop_override structure */
    OE_CHECK(oe_sgx_validate_enclave_properties(&props, NULL));

    /* If the OE_ENCLAVE_FLAG_DEBUG_AUTO is set and the OE_ENCLAVE_FLAG_DEBUG is
     * cleared, set enclave->debug based on the attributes in the properties. */
    if (!enclave->debug && oe_sgx_is_debug_auto_load_context(context))
        enclave->debug = props.config.attributes & OE_SGX_FLAGS_DEBUG;

    /* Update the flag in the context to ensure the flag will be set in SECS */
    if (enclave->debug)
        context->attributes.flags |= OE_ENCLAVE_FLAG_DEBUG;

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

    /* Calculate the number of pages needed for thread-local data */
    OE_CHECK(oeimage.get_tls_page_count(&oeimage, &tls_page_count));

    /* Calculate the size of this enclave in memory */
    OE_CHECK(_calculate_enclave_size(
        image_size,
        tls_page_count,
        &props,
        &loaded_enclave_pages_size,
        &enclave_size,
        &extra_data_size));

    /* Check if the enclave is configured with CapturePFGPExceptions=1 */
    if (props.config.flags.capture_pf_gp_exceptions)
    {
        /* Only opt into the feature if CPU (SGX2) supports the MISC region. */
        if (oe_sgx_is_misc_region_supported())
            context->capture_pf_gp_exceptions_enabled = 1;
#if !defined(OEHOSTMR) && defined(__linux__)
        else if (props.config.attributes & OE_SGX_FLAGS_DEBUG)
        {
            /* Enable #PF simulation (debug-mode only) */
            oe_sgx_host_enable_debug_pf_simulation();

            OE_TRACE_WARNING(
                "The enclave is configured with CapturePFGPExceptions=1 "
                "but the current CPU does not support the feature. The #PF "
                "simulation "
                "will be enabled (debug-mode only). To disable the simulation, "
                "setting "
                "CapturePFGPExceptions=0.\n");
        }
#endif
    }

    /* Check if the enclave is configured with CreateZeroBaseEnclave=1 */
    context->create_zero_base_enclave =
        props.config.flags.create_zero_base_enclave
            ? 1
            : 0; /* bool narrowing safe */

    context->start_address = props.config.start_address;

    if (enclave->simulate && context->create_zero_base_enclave)
    {
        OE_TRACE_ERROR(
            "Requested creation of 0-base enclave in simulation mode, "
            "which is currently not supported.\n");
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (props.config.attributes & OE_SGX_FLAGS_KSS)
    {
        if ((context->type == OE_SGX_LOAD_TYPE_CREATE) &&
            !oe_sgx_is_kss_supported())
        {
            // Fail if the CPU does not support KSS and the enclave specifies
            // the KSS flag
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "Enclave image was signed with kss flag but CPU doesn't "
                "support KSS\n",
                NULL);
        }
        context->attributes.flags |= OE_ENCLAVE_FLAG_SGX_KSS;
    }

    // if config_id data is passed and kss is not supported
    if (context->use_config_id && !oe_sgx_is_kss_supported())
    {
        if (!context->config_data->ignore_if_unsupported)
        {
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "Enclave image requires config_id/config_svn settings but "
                "Key Sharing and Seperation (KSS) is not supported on "
                "platform\n",
                NULL);
        }
        else
        {
            context->use_config_id = false;
        }
    }
    /* Perform the ECREATE operation */
    OE_CHECK(oe_sgx_create_enclave(
        context, enclave_size, loaded_enclave_pages_size, &enclave_addr));

    /* Save the enclave start address, base address, size, and text address */
    enclave->start_address = enclave_addr;
    enclave->base_address = context->create_zero_base_enclave
                                ? (uint64_t)OE_ADDRESS_ZERO
                                : enclave_addr;
    enclave->size = enclave_size;

    /* Patch image */
    OE_CHECK(oeimage.sgx_patch(&oeimage, enclave_size, extra_data_size));

    /* Add image to enclave */
    OE_CHECK(oeimage.add_pages(&oeimage, context, enclave, &vaddr));

    /* Add any extra data to the enclave */
    if (_oe_load_extra_enclave_data_hook)
    {
        oe_load_extra_enclave_data_hook_arg_t arg = {
            .magic = OE_LOAD_EXTRA_ENCLAVE_DATA_HOOK_ARG_MAGIC,
            .sgx_load_context = context,
            .enclave_base = enclave->base_address,
            .enclave_start = enclave->start_address,
            .base_vaddr = vaddr,
            .vaddr = 0,
        };
        OE_CHECK(_oe_load_extra_enclave_data_hook(
            &arg, enclave->start_address + vaddr));
        vaddr += arg.vaddr;
    }

#ifdef OE_WITH_EXPERIMENTAL_EEID
    OE_CHECK(_add_eeid_marker_page(
        context,
        enclave,
        image_size,
        tls_page_count,
        oeimage.elf.entry_rva,
        &props,
        &vaddr));
#endif

    /* Add data pages */
    OE_CHECK(_add_data_pages(
        context,
        enclave,
        &props,
        oeimage.elf.entry_rva,
        tls_page_count,
        &vaddr));

#ifdef OE_WITH_EXPERIMENTAL_EEID
    /* Add optional EEID pages */
    OE_CHECK(_add_eeid_pages(context, enclave_addr, &vaddr));

    /* Resign */
    OE_CHECK(_eeid_resign(context, &props));
#endif

    /* Ask the platform to initialize the enclave and finalize the hash */
    OE_CHECK(oe_sgx_initialize_enclave(
        context, enclave_addr, &props, &enclave->hash));

    /* Save full path of this enclave. When a debugger attaches to the host
     * process, it needs the fullpath so that it can load the image binary and
     * extract the debugging symbols. */
    enclave->path = get_fullpath(path);
    if (!enclave->path)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Set the magic number only if we have actually created an enclave */
    if (context->type == OE_SGX_LOAD_TYPE_CREATE)
        enclave->magic = ENCLAVE_MAGIC;

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

        debug_enclave->base_address = (void*)enclave->start_address;
        debug_enclave->size = enclave->size;

        debug_enclave->tcs_array =
            (sgx_tcs_t**)calloc(enclave->num_bindings, sizeof(sgx_tcs_t*));
        for (uint64_t i = 0; i < enclave->num_bindings; ++i)
        {
            debug_enclave->tcs_array[i] = (sgx_tcs_t*)enclave->bindings[i].tcs;
        }
        debug_enclave->tcs_count = enclave->num_bindings;

        debug_enclave->flags = 0;
        if (enclave->debug)
            debug_enclave->flags |= OE_DEBUG_ENCLAVE_MASK_DEBUG;
        if (enclave->simulate)
            debug_enclave->flags |= OE_DEBUG_ENCLAVE_MASK_SIMULATE;

        enclave->debug_enclave = debug_enclave;

        OE_CHECK(oeimage.sgx_get_debug_modules(
            &oeimage, enclave, &enclave->debug_modules));
    }

    result = OE_OK;

done:

    if (ecall_data)
        free(ecall_data);

    oe_unload_enclave_image(&oeimage);

    return result;
}

oe_result_t oe_get_ecall_id_table(
    oe_enclave_t* enclave,
    oe_ecall_id_t** ecall_id_table,
    uint64_t* ecall_id_table_size)
{
    oe_result_t result = OE_UNEXPECTED;
    if (!enclave || !ecall_id_table || !ecall_id_table_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    *ecall_id_table = enclave->ecall_id_table;
    *ecall_id_table_size = enclave->ecall_id_table_size;
    result = OE_OK;

done:
    return result;
}

oe_result_t oe_set_ecall_id_table(
    oe_enclave_t* enclave,
    oe_ecall_id_t* ecall_id_table,
    uint64_t ecall_id_table_size)
{
    oe_result_t result = OE_UNEXPECTED;
    if (!enclave || !ecall_id_table || !ecall_id_table_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    enclave->ecall_id_table = ecall_id_table;
    enclave->ecall_id_table_size = ecall_id_table_size;
    result = OE_OK;

done:
    return result;
}

#if !defined(OEHOSTMR)

#if __unix__

OE_NO_OPTIMIZE_BEGIN

OE_NEVER_INLINE static void _debug_non_debug_enclave_created_hook(
    const oe_debug_enclave_t* enclave)
{
    OE_UNUSED(enclave);
}

OE_NO_OPTIMIZE_END

#endif

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
    const oe_ecall_info_t* ecall_name_table,
    uint32_t ecall_count,
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
    enclave = (oe_enclave_t*)calloc(1, sizeof(oe_enclave_t));
    if (!enclave)
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the context parameter and any driver handles */
    OE_CHECK(oe_sgx_initialize_load_context(
        &context, OE_SGX_LOAD_TYPE_CREATE, flags));

#if defined(_WIN32)
    /* Create Windows events for each TCS binding. Enclaves use
     * this event when calling into the host to handle waits/wakes
     * as part of the enclave mutex and condition variable
     * implementation.
     */
    for (size_t i = 0; i < enclave->num_bindings; i++)
    {
        oe_thread_binding_t* binding = &enclave->bindings[i];

        binding->event.handle = CreateEvent(
            0,     /* No security attributes */
            FALSE, /* Event is reset automatically */
            FALSE, /* Event is not put in a signaled state upon creation */
            0);    /* No name */
        if (!binding->event.handle)
            OE_RAISE_MSG(OE_FAILURE, "CreateEvent failed", NULL);
    }

#endif

    for (size_t i = 0; i < setting_count; i++)
    {
        if (settings[i].setting_type == OE_SGX_ENCLAVE_CONFIG_DATA)
        {
            context.config_data = settings[i].u.config_data;
            context.use_config_id = true;
        }

#ifdef OE_WITH_EXPERIMENTAL_EEID
        if (settings[i].setting_type == OE_EXTENDED_ENCLAVE_INITIALIZATION_DATA)
        {
            context.eeid = settings[i].u.eeid;
        }
#endif
    }

    /* Build the enclave */
    OE_CHECK(oe_sgx_build_enclave(&context, enclave_path, NULL, enclave));

    /* Push the new created enclave to the global list. */
    if (oe_push_enclave_instance(enclave) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    // Notify debugger above the enclave and any modules.
    if (enclave->debug)
    {
        oe_debug_notify_enclave_created(enclave->debug_enclave);
        oe_debug_module_t* debug_module = enclave->debug_modules;
        while (debug_module)
        {
            oe_debug_module_t* next = debug_module->next;
            oe_debug_notify_module_loaded(debug_module);
            debug_module = next;
        }
    }
    else
    {
#if __unix__
        // Call hook function so that debugger (if any) can emit a warning
        // message.
        oe_debug_enclave_t debug_enclave = {0};

        debug_enclave.magic = OE_DEBUG_ENCLAVE_MAGIC;
        debug_enclave.version = OE_DEBUG_ENCLAVE_VERSION;
        debug_enclave.next = NULL;

        debug_enclave.path = enclave->path;
        debug_enclave.path_length = strlen(enclave->path);

        _debug_non_debug_enclave_created_hook(&debug_enclave);
#endif
    }

    /* Enclave initialization invokes global constructors which could make
     * ocalls. Therefore setup ocall table prior to initialization. */
    enclave->ocalls = (const oe_ocall_func_t*)ocall_table;
    enclave->num_ocalls = ocall_count;

    /* Register ecalls */
    enclave->num_ecalls = ecall_count;
    oe_register_ecalls(enclave, ecall_name_table, ecall_count);

    /* Invoke enclave initialization. */
    OE_CHECK(_initialize_enclave(enclave));

    /* Setup logging configuration */
    if (oe_log_enclave_init(enclave) == OE_UNSUPPORTED)
    {
        OE_TRACE_WARNING(
            "In-enclave logging is not supported. To enable, please add \n\n"
            "from \"openenclave/edl/logging.edl\" import *;\n\n"
            "in the edl file.\n");
    }

    /* Apply the list of settings to the enclave.
     * This may initialize switchless manager too.
     * Doing this as the last step in enclave initialization ensures
     * that all the ecalls necessary for enclave initialization have already
     * been executed. Now all available tcs can be taken up by ecall worker
     * threads. If we initialize the switchless manager earlier, then any
     * normal ecalls required for initialization may not complete if all the
     * tcs are taken up by ecall worker threads.
     */
    OE_CHECK(_configure_enclave(enclave, settings, setting_count));

    OE_TRACE_INFO("oe_create_enclave succeeded");

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

    /* Call the atexit functions (e.g., registered by atexit or the
     * destructor attribute) */
    result = oe_ecall(enclave, OE_ECALL_CALL_AT_EXIT_FUNCTIONS, 0, NULL);
    /* The ECALL is expected to fail if running out the number of TCS (e.g.,
     * when requesting too many host or enclave workers for switchless calls).
     * Do not fall through in this case to continue the enclave termination and
     * throw error messages. */
    if (result == OE_OUT_OF_THREADS)
        OE_TRACE_ERROR(
            "invoking enclave atexit functions failed, please increase "
            "the NumTCS value in the enclave configuration file\n");
    else if (result != OE_OK)
        OE_RAISE(result);

    /* Shut down the switchless manager after calling exit functions, which
     * allows the exit functions to use switchless OCALLs and ECALLs (nested) */
    OE_CHECK(oe_stop_switchless_manager(enclave));

    /* Call the enclave destructor */
    OE_CHECK(oe_ecall(enclave, OE_ECALL_DESTRUCTOR, 0, NULL));

    if (enclave->debug_enclave)
    {
        while (enclave->debug_enclave->modules)
        {
            oe_debug_module_t* module = enclave->debug_enclave->modules;
            oe_debug_notify_module_unloaded(module);
            // Notification removes the module from the list of modules.
            // Free the module here.
            free((void*)module->path);
            free(module);
        }

        oe_debug_notify_enclave_terminated(enclave->debug_enclave);
        free(enclave->debug_enclave->tcs_array);
        free(enclave->debug_enclave);
    }

    /* Destroy the ecall id table */
    if (enclave->ecall_id_table)
        free(enclave->ecall_id_table);

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

        for (size_t i = 0; i < enclave->num_bindings; i++)
        {
            oe_thread_binding_t* binding = &enclave->bindings[i];
#if defined(_WIN32)
            /* Release Windows events created during enclave creation */
            CloseHandle(binding->event.handle);
#endif
            free(binding->ocall_buffer);
        }

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
