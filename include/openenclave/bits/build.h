#ifndef _OE_BUILD_H
#define _OE_BUILD_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>
#include <openenclave/sha.h>
#include "sgxdev.h"
#include "sgxtypes.h"

OE_EXTERNC_BEGIN

#define OE_SGX_MAX_TCS 32

typedef struct _OE_Enclave OE_Enclave;

OE_SGXDevice* __OE_OpenSGXDriver(bool simulate);

OE_SGXDevice* __OE_OpenSGXMeasurer(void);

OE_Result __OE_BuildEnclave(
    OE_SGXDevice* dev,
    const char* path,
    const OE_EnclaveSettings* settings,
    bool debug,
    bool simulate,
    OE_Enclave* enclave);

OE_EXTERNC_END

#endif /* _OE_BUILD_H */
