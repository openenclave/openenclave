// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_TESTS_H
#define _OE_INTERNAL_SGX_TESTS_H

#include <openenclave/bits/defs.h>

OE_EXTERNC_BEGIN

/*
 * Return whether SGX quote provider libraries are available in the system.
 */
bool oe_has_sgx_quote_provider(void);

OE_EXTERNC_END

#endif // _OE_INTERNAL_SGX_TESTS_H
