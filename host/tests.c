#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <stdlib.h>

oe_uint32_t OE_GetCreateFlags(void)
{
    char* env = getenv("OE_SIMULATION");

    if (env && strcmp(env, "1") == 0)
    {
        return OE_FLAG_DEBUG | OE_FLAG_SIMULATE;
    }

    return OE_FLAG_DEBUG;
}
