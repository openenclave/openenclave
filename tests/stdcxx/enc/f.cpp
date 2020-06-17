// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>

extern size_t num_constructions;
extern size_t num_destructions;

class f
{
  public:
    f()
    {
        num_constructions++;
        printf("f::f()\n");
    }

    ~f()
    {
        num_destructions++;
        printf("f::~f()\n");
    }
};

f _f0;
f _f1;
f _f2;
