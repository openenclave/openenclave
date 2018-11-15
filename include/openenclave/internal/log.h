// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LOG_H
#define _OE_LOG_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Maximum log length */
#define OE_LOG_MODULE_LEN_MAX 32
#define OE_LOG_MESSAGE_LEN_MAX 256

enum { LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR };

typedef struct _oe_log_args
{
    char module[OE_LOG_MODULE_LEN_MAX];
    char message[OE_LOG_MESSAGE_LEN_MAX];
    uint8_t level;
} oe_log_args_t;

OE_EXTERNC_END

#endif /* _OE_LOG_H */
