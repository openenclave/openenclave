// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../args.h"
#include "encryptor.h"

template <typename T>
bool is_outside_enclave(T* args)
{
    if (oe_is_outside_enclave(args, sizeof(T)))
        return true;
    return false;
}

#define DISPATCH(x)                          \
    if (!is_outside_enclave(args))           \
    {                                        \
        args->result = OE_INVALID_PARAMETER; \
        return;                              \
    }                                        \
    dispatcher.x(args);

// Declare a static dispatcher object for enabling for better organization
// enclave-wise global variables
static ECallDispatcher dispatcher;

// OE calls
OE_ECALL void InitializeEncryptor(EncryptInitializeArgs* args)
{
    DISPATCH(Initialize);
}

OE_ECALL void EncryptBlock(EncryptBlockArgs* args)
{
    DISPATCH(EncryptBlock);
}

OE_ECALL void CloseEncryptor(CloseEncryptorArgs* args)
{
    DISPATCH(close);
}
