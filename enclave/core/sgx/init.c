// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "init.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/jump.h>
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

static void _initialize_enclave_image()
{
    /* Relocate symbols */
    if (!oe_apply_relocations())
    {
        oe_abort();
    }

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
