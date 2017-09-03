#include <openenclave.h>
#include <oeinternal/calls.h>

int OE_HostPuts(const char* str)
{
    int ret = -1;
    char* hstr = OE_NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (__OE_OCall(OE_FUNC_PUTS, (oe_uint64_t)hstr, OE_NULL) != OE_OK)
        goto done;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}
