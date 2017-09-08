#include <openenclave/enclave.h>

void __OE_AssertFail(
    const char *expr,
    const char *file,
    int line,
    const char *function)
{
    char buf[1024];

    /* ATTN: using fixed-length buffer here! */

    OE_Snprintf(buf, sizeof(buf), "Assertion failed: %s (%s: %s: %d)\n",
        expr, file, function, line);
    OE_HostPrint(buf);
    OE_Abort();
}
