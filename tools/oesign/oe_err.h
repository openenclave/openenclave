// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>

void oe_set_err_program_name(const char* name);

OE_PRINTF_FORMAT(1, 2)
void oe_err(const char* format, ...);

void oe_print_err_count();

#define OE_CHECK_ERR(EXPRESSION, err_fmt, ...) \
    do                                         \
    {                                          \
        result = (EXPRESSION);                 \
        if (result != OE_OK)                   \
        {                                      \
            oe_err(err_fmt, ##__VA_ARGS__);    \
            goto done;                         \
        }                                      \
    } while (0)
