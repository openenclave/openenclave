// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OELOG_ENCLAVE_H
#define _OELOG_ENCLAVE_H

#include <openenclave/enclave.h>
#include <openenclave/internal/oelog-common.h>

OE_EXTERNC_BEGIN

oe_result_t oe_log(log_level_t level, const char* module, const char* fmt, ...);

OE_EXTERNC_END

#endif /* _OELOG_ENCLAVE_H */
