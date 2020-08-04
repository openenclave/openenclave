// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "init.h"
#include <openenclave/advanced/allocator.h>
#include <openenclave/bits/eeid.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/eeid.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>
#include "asmdefs.h"
#include "td.h"

/*
**==============================================================================
**
** _check_memory_boundaries()
**
**     Check that the variables in globals.h are actually within the enclave.
**
**==============================================================================
*/

static void _check_memory_boundaries(void)
{
    /* This is a tautology! */
    if (!oe_is_within_enclave(__oe_get_enclave_base(), __oe_get_enclave_size()))
        oe_abort();

    if (!oe_is_within_enclave(__oe_get_reloc_base(), __oe_get_reloc_size()))
        oe_abort();

    if (!oe_is_within_enclave(__oe_get_heap_base(), __oe_get_heap_size()))
        oe_abort();
}

#ifdef OE_WITH_EXPERIMENTAL_EEID
extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;
extern oe_eeid_t* oe_eeid;

static int _is_eeid_base_image(
    const volatile oe_sgx_enclave_properties_t* properties)
{
    return properties->header.size_settings.num_heap_pages == 0 &&
           properties->header.size_settings.num_stack_pages == 0 &&
           properties->header.size_settings.num_tcs == 1;
}

static oe_result_t _eeid_patch_memory()
{
    oe_result_t r = OE_OK;

    if (_is_eeid_base_image(&oe_enclave_properties_sgx))
    {
        uint8_t* enclave_base = (uint8_t*)__oe_get_enclave_base();
        uint8_t* heap_base = (uint8_t*)__oe_get_heap_base();
        const oe_eeid_marker_t* marker = (oe_eeid_marker_t*)heap_base;
        oe_eeid_t* eeid = (oe_eeid_t*)(enclave_base + marker->offset);

        /* EEID must be within the enclave memory */
        if (!oe_is_within_enclave(eeid, sizeof(oe_eeid_t)) ||
            !oe_is_within_enclave(
                eeid->data, eeid->data_size + eeid->signature_size))
            oe_abort();

        oe_eeid = eeid;

        uint8_t* heap_end = (uint8_t*)__oe_get_heap_end();
        uint8_t* tcs_end =
            heap_end + (OE_SGX_TCS_CONTROL_PAGES + OE_SGX_TCS_GUARD_PAGES +
                        eeid->size_settings.num_stack_pages) *
                           OE_PAGE_SIZE * eeid->size_settings.num_tcs;

        /* EEID must not overlap with tcs/stack/control pages */
        if ((uint8_t*)eeid < tcs_end)
            oe_abort();

        // Wipe the marker page
        memset(heap_base, 0, OE_PAGE_SIZE);
    }

    return r;
}
#endif

static void _initialize_enclave_image()
{
    /* Relocate symbols */
    if (!oe_apply_relocations())
    {
        oe_abort();
    }

#ifdef OE_WITH_EXPERIMENTAL_EEID
    if (_eeid_patch_memory() != OE_OK)
    {
        oe_abort();
    }
#endif

    /* Check that memory boundaries are within enclave */
    _check_memory_boundaries();
}

static oe_once_t _enclave_initialize_once;

static void _initialize_enclave_imp(void)
{
    _initialize_enclave_image();
}

/*
**==============================================================================
**
** oe_initialize_enclave()
**
**     This function is called the first time the enclave is entered. It
**     performs any necessary enclave initialization, such as applying
**     relocations, initializing exception etc.
**
**==============================================================================
*/
void oe_initialize_enclave()
{
    oe_once(&_enclave_initialize_once, _initialize_enclave_imp);
}
