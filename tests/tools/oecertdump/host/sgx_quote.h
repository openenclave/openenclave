// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _SGX_QUOTE
#define _SGX_QUOTE

#include <openenclave/host.h>
#include "../../../../host/sgx/platformquoteprovider.h"

void log(const char* fmt, ...);
void oecertdump_quote_provider_log(
    sgx_ql_log_level_t level,
    const char* message);
void set_log_callback();

oe_result_t gen_report(oe_enclave_t* enclave);

#endif // _SGX_QUOTE