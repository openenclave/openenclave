// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCGEN_TYPES_H
#define _ENCGEN_TYPES_H

#include <string>

struct PredefinedType
{
    const char* idlName; // Name of type as it appears in a .idl file
    const char* genName; // Name of type as it appears in generated code.
    const char* genType; // Name of type tag as it appears in generated code.
};

extern PredefinedType types[];
extern size_t ntypes;

#endif /* _ENCGEN_TYPES_H */
