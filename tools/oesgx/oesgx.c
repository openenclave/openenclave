// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../host/cpuid.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct _Regs
{
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
} Regs;

static int _CPUID(Regs* regs)
{
    unsigned int leaf_requested = regs->eax;
    int result = 0;

    oe_get_cpuid(leaf_requested, 
        &regs->ecx, &regs->eax, &regs->ebx, &regs->ecx, &regs->edx);
    
    // Check if results indicate unsupported leaf.
    if (leaf_requested > regs->eax || 
        regs->eax == 0 && regs->ebx == 0 && regs->ecx == 0 && regs->edx == 0)
    {
        printf("Error getting CPUID. Returned: %d", regs->eax);
        result = 1;
    }
    return result;
}

#define HAVE_SGX(regs) (((regs.ebx) >> 2) & 1)

#define HAVE_SGX1(regs) (((regs.eax) & 1))

#define HAVE_SGX2(regs) (((regs.eax) >> 1) & 1)

int main(int argc, const char* argv[])
{
    int result = 0;

    if (argc != 1)
    {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        exit(1);
    }

    /* Figure out whether CPU supports SGX */
    {
        Regs regs = {0x7, 0, 0x0, 0};

        result = _CPUID(&regs);
        if (result)
        {
            return result;
        }

        if (!HAVE_SGX(regs))
        {
            printf("0\n");
            return 0;
        }
    }

    /* Figure out whether CPU supports SGX-1 or SGX-2 */
    {
        Regs regs = {0x12, 0, 0x0, 0};

        result = _CPUID(&regs);
        if (result)
        {
            return result;
        }

        if (HAVE_SGX2(regs))
        {
            printf("2\n");
            return 0;
        }
        if (HAVE_SGX1(regs))
        {
            printf("1\n");
            return 0;
        }
    }

    printf("0\n");

    return 0;
}
