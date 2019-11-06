// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_HOST_STRINGS_H
#define _OE_HOST_STRINGS_H

#include <stddef.h>

char* oe_strdup(const char* str);

size_t oe_strlcpy(char* dest, const char* src, size_t size);

size_t oe_strlcat(char* dest, const char* src, size_t size);

#endif /* _OE_HOST_STRINGS_H */
