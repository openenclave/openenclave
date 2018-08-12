// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#include <openenclave/internal/calls.h>

typedef struct _PasswordArgs
{
    unsigned char *password;
    unsigned int size;
    oe_result_t result;
} PasswordArgs;


typedef struct _EncryptArgs
{
    bool b_encrypt;
    unsigned int size;
    oe_result_t result;
} EncryptArgs;


typedef struct _EncryptBlockArgs
{
    bool b_encrypt;
    unsigned char *inputbuf;
    unsigned char *outputbuf;
    unsigned int size;
    oe_result_t result;
} EncryptBlockArgs;

typedef struct _CloseEncryptorArgs
{
    bool b_encrypt;
    unsigned char *in;
    unsigned char *out;
    unsigned int  size;
    oe_result_t result;
} CloseEncryptorArgs;


#endif /* _ARGS_H */
