#include <openenclave.h>
#include "../args.h"

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;
    const char data[] = "abcdefghijklmnopqrstuvwxyz";

    OE_SHA256Context ctx;
    OE_SHA256Init(&ctx);
    OE_SHA256Update(&ctx, data, sizeof(data)-1);
    OE_SHA256Final(&ctx, &args->hash);

    (void)args;
}
