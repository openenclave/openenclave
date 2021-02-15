// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/trace.h>

#include "core_u.h"

/* A dummy ocall used to check if the logging.edl is imported. */
void oe_log_is_supported_ocall()
{
}

void oe_log_ocall(uint32_t log_level, const char* message)
{
    oe_log_message(true, (oe_log_level_t)log_level, message);
}
