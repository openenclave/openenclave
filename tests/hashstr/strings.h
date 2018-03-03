// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef __STRINGS_H
#define __STRINGS_H

#include <stddef.h>

typedef struct Pair
{
    unsigned long code;
    const char* str;
} Pair;

extern Pair strings[];
extern long nstrings;

#endif /* __STRINGS_H */
