// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

typedef struct
{
    int x;
    int y;
} my_type1;

typedef my_type1* my_type2;

typedef my_type1 my_type3[10];
