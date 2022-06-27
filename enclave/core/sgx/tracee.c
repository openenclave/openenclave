// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include <openenclave/internal/sgx/td.h>

#include "../tracee.h"
#include "report.h"
#include "tracee.h"

static volatile int _is_enclave_debug_allowed = -1;
static volatile int _is_in_simulation_mode = -1;

oe_result_t oe_sgx_initialize_simulation_mode_cache(oe_sgx_td_t* td)
{
    int simulation_mode =
        __atomic_load_n(&_is_in_simulation_mode, __ATOMIC_ACQUIRE);
    oe_result_t result = OE_OK;

    if (simulation_mode != -1)
        goto done;

    if (!td)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The td->simulate is set by the host (see _enter_sim in host/sgx/calls.c)
     */
    simulation_mode = td->simulate ? true : false;

    __atomic_store_n(
        &_is_in_simulation_mode, simulation_mode, __ATOMIC_RELEASE);

done:
    return result;
}

/* Determine if the enclave is in simulation mode based on the cached value. If
 * the cached value is not initialized yet, the function returns false. */
bool oe_sgx_is_in_simulation_mode()
{
    int simulation_mode =
        __atomic_load_n(&_is_in_simulation_mode, __ATOMIC_ACQUIRE);

    if (simulation_mode != -1)
        goto done;

done:
    return simulation_mode == 1 ? true : false;
}

// Read an enclave's identity attribute to see to if it was signed as an debug
// enclave
bool oe_is_enclave_debug_allowed()
{
    int debug_allowed =
        __atomic_load_n(&_is_enclave_debug_allowed, __ATOMIC_ACQUIRE);

    if (debug_allowed != -1)
        goto done;

    // Start off by assuming debug is not allowed.
    debug_allowed = 0;

    if (oe_sgx_is_in_simulation_mode())
    {
        // Enclave in simulate mode is treated as debug_allowed
        debug_allowed = 1;
    }
    else
    {
        // Get a report on the enclave itself for enclave identity information
        sgx_report_t sgx_report;
        oe_result_t result = sgx_create_report(NULL, 0, NULL, 0, &sgx_report);

        if (result == OE_OK)
        {
            debug_allowed =
                (sgx_report.body.attributes.flags & SGX_FLAGS_DEBUG) ? 1 : 0;
        }
    }

    __atomic_store_n(
        &_is_enclave_debug_allowed, debug_allowed, __ATOMIC_RELEASE);

done:
    return debug_allowed == 1 ? true : false;
}
