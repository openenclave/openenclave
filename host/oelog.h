// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_LOG_H
#define _OE_HOST_LOG_H

#include <stdio.h>
#include <openenclave/internal/oelog.h>

void _oe_log(bool enclave, oe_log_args_t *args);

#endif //_OE_HOST_LOG_H
