// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OELOG_HOST_H
#define _OELOG_HOST_H

#include <stdio.h>
#include <openenclave/internal/oelog-common.h>

OE_EXTERNC_BEGIN

int oe_log_init(const char *path, log_level_t level);
oe_result_t oe_log_enclave_init(oe_enclave_t* enclave, log_level_t level);
void oe_log_close(void);

OE_EXTERNC_END

#endif //_OELOG_HOST_H
