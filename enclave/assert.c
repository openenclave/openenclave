#include <openenclave/enclave.h>

void __OE_AssertFail(
    const char *expr,
    const char *file,
    int line,
    const char *function)
{
    OE_HostPrintf("Assertion failed: %s (%s: %s: %d)\n",
        expr, file, function, line);
    OE_Abort();
}
