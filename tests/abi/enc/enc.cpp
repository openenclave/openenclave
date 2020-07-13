// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "abi_t.h"

double enclave_add_float()
{
    double my_res = 0;
    volatile double my_num = 0.12345678899;

    asm("fldl %1\n\t"
        "fadd %%st, %%st\n\t"
        "fstl %0\n\t"
        : "=m"(my_res)
        : "m"(my_num)
        :);

    return my_res;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
