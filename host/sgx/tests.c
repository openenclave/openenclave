// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/sgx/tests.h>
#include "../hostthread.h"
#include "sgxquoteprovider.h"

static bool _has_quote_provider = false;

static void _check_quote_provider(void)
{
    _has_quote_provider = (oe_initialize_quote_provider() == OE_OK);
}

bool oe_has_sgx_quote_provider(void)
{
    static oe_once_type once = OE_H_ONCE_INITIALIZER;
    oe_once(&once, _check_quote_provider);
    return _has_quote_provider;
}
