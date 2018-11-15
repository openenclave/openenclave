// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef LOG_HOST_H
#define LOG_HOST_H

#include <stdio.h>
#include <openenclave/bits/log-common.h>

int log_init(uint8_t level, const char *path);
void log_close(void);

#endif //LOG_HOST_H
