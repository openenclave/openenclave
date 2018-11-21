/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once
#ifndef _OE_ENCLAVE_H
# include <openenclave/enclave.h>
#endif
#ifndef OE_USE_OPTEE
# error sgxoveroptee_enclave.h should only be included with OE_USE_OPTEE
#endif

#ifdef _MSC_VER
#pragma warning( push )  
#pragma warning( disable : 4200 )  
#pragma warning( disable : 4201 )  
#endif
#include <tee_api_types.h>
#ifdef _MSC_VER
#pragma warning( pop ) 
#endif
#include "sgxoveroptee.h"

sgx_status_t
sgx_optee_ocall(
    const unsigned int index,
    void* buffer,
    size_t bufferSize);
