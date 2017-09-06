#include <stdio.h>
#include <stdlib.h>

typedef struct _Regs
{
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
}
Regs;

static void _CPUID(Regs* regs)
{
    asm volatile(
        "cpuid"
        :
        "=a"(regs->eax),
        "=b"(regs->ebx),
        "=c"(regs->ecx),
        "=d"(regs->edx)
        :
        "0"(regs->eax),
        "2"(regs->ecx));
}

#define HAVE_SGX(regs) (((regs.ebx) >> 2) & 1)

#define HAVE_SGX1(regs) (((regs.eax) & 1))

#define HAVE_SGX2(regs) (((regs.eax) >> 1) & 1)

int main(int argc, const char* argv[])
{
    if (argc != 1)
    {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        exit(1);
    }

    /* Figure out whether CPU supports SGX */
    {
        Regs regs = { 0x7, 0, 0x0, 0 };

        _CPUID(&regs);

        if (!HAVE_SGX(regs))
        {
            printf("0\n");
            return 0;
        }
    }

    /* Figure out whether CPU supports SGX-1 or SGX-2 */
    {
        Regs regs = { 0x12, 0, 0x0, 0 };

        _CPUID(&regs);

        if (HAVE_SGX1(regs))
        {
            printf("1\n");
            return 0;
        }
        if (HAVE_SGX2(regs))
        {
            printf("2\n");
            return 0;
        }
    }
       
    printf("0\n");

    return 0;
}
