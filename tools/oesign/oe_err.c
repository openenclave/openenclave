// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "oe_err.h"
#include <stdarg.h>
#include <stdio.h>

static size_t _err_count = 0;
static const char* _program_name = "***";

void oe_set_err_program_name(const char* name)
{
    if (name)
        _program_name = name;
}

OE_PRINTF_FORMAT(1, 2)
void oe_err(const char* format, ...)
{
    fprintf(stderr, "%s ERROR: ", _program_name);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");

    _err_count++;
}

void oe_print_err_count()
{
    if (_err_count)
    {
        fprintf(
            stderr, "%s encountered %zu errors\n", _program_name, _err_count);
    }
}
