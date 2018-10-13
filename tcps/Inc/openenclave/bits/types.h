#pragma once
#ifdef TRUSTED_CODE
#include <tcps_t.h>
#endif
#ifdef UNTRUSTED_CODE
#include <tcps_u.h>
#endif

#ifndef _OE_BITS_TYPES_H
typedef enum _oe_enclave_type {
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
} oe_enclave_type_t;
typedef void oe_enclave_t;
#define _OE_BITS_TYPES_H
#endif

typedef void (*oe_call_t)(
    void* inBuffer,
    size_t inBufferSize,
    void* outBuffer,
    size_t outBufferSize,
    size_t* outBufferSizeWritten);
