#ifndef _ENCIDL_PINGPONG_U_H
#define _ENCIDL_PINGPONG_U_H

#include <openenclave/host.h>

/*
********************************************************************************
**
** Structure definitions
**
********************************************************************************
*/

/*
********************************************************************************
**
** Inbound calls
**
********************************************************************************
*/

OE_EXTERNC void Pong(
    const char *in,
    char out[128]);

OE_EXTERNC void Log(
    const char *str,
    oe_uint64_t x);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result Ping(
    OE_Enclave* enclave,
    const char *in,
    char out[128]);

#endif /* _ENCIDL_PINGPONG_U_H */
