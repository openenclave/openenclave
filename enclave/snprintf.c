#include <openenclave/enclave.h>

int OE_Snprintf(char* str, size_t size, const char* fmt, ...)
{
    OE_va_list ap;
    OE_va_start(ap, fmt);
    int n = OE_Vsnprintf(str, size, fmt, ap);
    OE_va_end(ap);
    return n;
}
