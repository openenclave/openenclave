#include <openenclave/internal/trace.h>
#include <openenclave/bits/defs.h>

oe_result_t oe_log(log_level_t level, const char* fmt, ...)
{
    OE_UNUSED(level);
    OE_UNUSED(fmt);
    return OE_UNSUPPORTED;
}

int oe_host_fprintf(int device, const char* fmt, ...)
{
    OE_UNUSED(device);
    OE_UNUSED(fmt);
    return -1;
}
