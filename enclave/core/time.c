#include <openenclave/internal/time.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/hostalloc.h>

int oe_sleep_ocall(uint64_t milliseconds)
{
    size_t ret = -1;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (oe_ocall(OE_OCALL_SLEEP, (uint64_t)milliseconds, NULL, flags) != OE_OK)
        goto done;

    ret = 0;

done:

    return ret;
}

uint64_t oe_untrusted_time_ocall(void)
{
    uint64_t ret = 0;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (oe_ocall(OE_OCALL_UNTRUSTED_TIME, 0, &ret, flags) != OE_OK)
    {
        ret = 0;
        goto done;
    }

done:

    return ret;
}
