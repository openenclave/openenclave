// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOST_LOG_H
#define _OE_HOST_LOG_H

#include <stdio.h>
//#include <stdarg.h>
#include <openenclave/internal/log.h>

int log_init(int level, const char *path);
void log_log(const char *enclave, oe_log_args_t *args);
void log_close();

#endif //_OE_HOST_LOG_H
