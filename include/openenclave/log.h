// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_LOG_H
#define _OE_LOG_H

OE_EXTERNC_BEGIN

typedef enum _oe_log_level
{
    OE_LOG_LEVEL_NONE = 0,
    OE_LOG_LEVEL_FATAL,
    OE_LOG_LEVEL_ERROR,
    OE_LOG_LEVEL_WARNING,
    OE_LOG_LEVEL_INFO,
    OE_LOG_LEVEL_VERBOSE,
    OE_LOG_LEVEL_MAX
} oe_log_level_t;

extern const char* const oe_log_level_strings[OE_LOG_LEVEL_MAX];

OE_EXTERNC_END

#endif
