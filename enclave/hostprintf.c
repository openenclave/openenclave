#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>

int OE_HostPrintf(const char* fmt, ...)
{
    char buf[1024];

    OE_va_list ap;
    OE_va_start(ap, fmt);
    int n = OE_Vsnprintf(buf, sizeof(buf), fmt, ap);
    OE_va_end(ap);

    OE_HostPuts(buf);

    return n;
}
