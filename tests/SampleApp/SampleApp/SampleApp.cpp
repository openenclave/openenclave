#include <openenclave/enclave.h>

const char* ProtectedMessage = "Hello world from Enclave\n\0";

int HostUnsecureStrPatching(const char* src, char* dst, int dstLength);

int SecureStrPatching(const char* src, char* dst, int dstLength)
{
    if (!OE_IsOutsideEnclave(dst, dstLength))
    {
        return -1;
    }
    if (!OE_IsOutsideEnclave(src, 1))
    {
        return -1;
    }
    const char* runningSrc = src;
    int runningLength = dstLength;
    while (runningLength > 0 && *runningSrc != '\0')
    {
        *dst = *runningSrc;
        runningLength--;
        runningSrc++;
        dst++;
        if (!OE_IsOutsideEnclave(runningSrc, 1))
        {
            return -1;
        }
    }
    const char* ptr = ProtectedMessage;
    while (runningLength > 0 && *ptr != '\0')
    {
        *dst = *ptr;
        runningLength--;
        ptr++;
        dst++;
    }
    if (runningLength < 1)
    {
        return -1;
    }
    *dst = '\0';
    return HostUnsecureStrPatching(src, dst, dstLength);
}
