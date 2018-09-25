// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

extern size_t num_constructions;
extern size_t num_destructions;

class F
{
  public:
    F()
    {
        num_constructions++;
        printf("F::F()\n");
    }

    ~F()
    {
        num_destructions++;
        printf("F::~F()\n");
    }
};

F _f0;
F _f1;
F _f2;
