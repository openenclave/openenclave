#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <stdlib.h>
#include "dupenv.h"

uint32_t OE_GetCreateFlags(void)
{
    char* env = Dupenv("OE_SIMULATION");

    if (env && strcmp(env, "1") == 0)
    {
        free(env);
        return OE_FLAG_DEBUG | OE_FLAG_SIMULATE;
    }

    free(env);
    return OE_FLAG_DEBUG;
}
