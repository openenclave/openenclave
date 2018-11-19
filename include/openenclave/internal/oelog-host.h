// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OELOG_HOST_H
#define _OELOG_HOST_H

#include <stdio.h>
#include <openenclave/internal/oelog-common.h>

int oe_log_init(const char *path, log_level_t level);
int oe_log_enclave_init(oe_enclave_t* enclave, log_level_t level);

void log_log(const char *enclave, oe_log_args_t *args);
void oe_log_close(void);

#endif //_OELOG_HOST_H
