
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/thread.h>

#include "calls.h"

/*
**==============================================================================
**
** oe_register_ecall_function_table()
**
** Register an ecall table with the given table_id.
**
**==============================================================================
*/

ecall_table_t _ecall_tables[OE_MAX_ECALL_TABLES];
static oe_spinlock_t _ecall_tables_lock = OE_SPINLOCK_INITIALIZER;

oe_result_t oe_register_ecall_function_table(
    uint64_t table_id,
    const oe_ecall_func_t* ecalls,
    size_t num_ecalls)
{
    oe_result_t result = OE_UNEXPECTED;

    if (table_id >= OE_MAX_ECALL_TABLES || !ecalls)
        OE_RAISE(OE_INVALID_PARAMETER);

    oe_spin_lock(&_ecall_tables_lock);
    _ecall_tables[table_id].ecalls = ecalls;
    _ecall_tables[table_id].num_ecalls = num_ecalls;
    oe_spin_unlock(&_ecall_tables_lock);

    result = OE_OK;

done:
    return result;
}
