// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVE_LOG_H
#define _OE_ENCLAVE_LOG_H

#include <openenclave/enclave.h>

oe_result_t _handle_oelog_init(uint64_t arg);
oe_result_t _handle_oelog_close(uint64_t arg);

#endif /* _OE_ENCLAVE_LOG_H */
