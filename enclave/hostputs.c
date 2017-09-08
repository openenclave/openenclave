#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>

int OE_HostPuts(const char* str)
{
    int ret = -1;
    char* hstr = NULL;

    if (!str)
        goto done;

    if (!(hstr = OE_HostStrdup(str)))
        goto done;

    if (__OE_OCall(OE_FUNC_PUTS, (uint64_t)hstr, NULL) != OE_OK)
        goto done;

    ret = 0;

done:

    if (hstr)
        OE_HostFree(hstr);

    return ret;
}
