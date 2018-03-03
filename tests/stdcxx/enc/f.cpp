// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

extern size_t numConstructions;
extern size_t numDestructions;

class F
{
  public:
    F()
    {
        numConstructions++;
        printf("F::F()\n");
    }

    ~F()
    {
        numDestructions++;
        printf("F::~F()\n");
    }
};

F _f0;
F _f1;
F _f2;
