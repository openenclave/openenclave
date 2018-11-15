// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_LOG_H
#define _OE_HOST_LOG_H

#include <stdio.h>
#include <openenclave/internal/log.h>
#include <openenclave/bits/log-host.h>

void log_log(const char *enclave, oe_log_args_t *args);

#endif //_OE_HOST_LOG_H
