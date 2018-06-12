// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <stdio.h>
#include <stdlib.h>

static const char* _programName = "";

void oe_set_program_name(const char* name)
{
    _programName = name;
}

OE_PRINTF_FORMAT(3, 4)
void __oe_put_err(const char* file, unsigned int line, const char* format, ...)
{
    fprintf(stderr, "%s: %s(%u): error: ", _programName, file, line);

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);

    fprintf(stderr, "\n");
    exit(1);
}
