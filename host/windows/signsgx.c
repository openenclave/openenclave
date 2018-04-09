#include <openenclave/bits/build.h>
#include <openenclave/result.h>

OE_Result OE_SignEnclave_SGX(
    const OE_SHA256* mrenclave,
    uint16_t productID,
    uint16_t securityVersion,
    const char* pemData,
    size_t pemSize,
    SGX_SigStruct* sigstruct)
{
    /* ATTN: unsupported on Windows */
    return OE_UNSUPPORTED;
}
