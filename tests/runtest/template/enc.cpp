#include <openenclave/enclave.h>
#include "../args.h"

extern "C" int main(int argc, const char* argv[]);

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        static const char* argv[] = { "test", NULL, };
        static int argc = sizeof(argv) / sizeof(argv[0]);
        args->ret = main(argc, argv);
        args->test = OE_HostStrdup("test");
    }
}
