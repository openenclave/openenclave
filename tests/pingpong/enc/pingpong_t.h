#ifndef _ENCIDL_PINGPONG_T_H
#define _ENCIDL_PINGPONG_T_H

#include <openenclave/enclave.h>

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

OE_EXTERNC void Ping(
    const char *in,
    char out[128]);

/*
********************************************************************************
**
** Outbound calls
**
********************************************************************************
*/

OE_EXTERNC OE_Result Pong(
    const char *in,
    char out[128]);

OE_EXTERNC OE_Result Log(
    const char *str,
    uint64_t x);

#endif /* _ENCIDL_PINGPONG_T_H */
