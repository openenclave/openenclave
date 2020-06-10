// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_CORE_THREADLOCAL_H
#define _OE_CORE_THREADLOCAL_H

#include <openenclave/enclave.h>
#include "td.h"

OE_EXTERNC_BEGIN

/**
 * Initialize the thread-local section for a given thread.
 * This must be called immediately after td itself is initialized.
 */
oe_result_t oe_thread_local_init(oe_sgx_td_t* td);

/**
 * Cleanup the thread-local section for a given thread.
 * This must be called *before* the td itself is cleaned up.
 */
oe_result_t oe_thread_local_cleanup(oe_sgx_td_t* td);

OE_EXTERNC_END

#endif // _OE_CORE_THREADLOCAL_H
