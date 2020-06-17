// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _ARGS_H
#define _ARGS_H

#define DATA_SIZE 1024

typedef struct _args
{
    /* Enclave converts this data buffer into a hex string */
    unsigned char data[DATA_SIZE];

    /* Enclave writes result of conversion to this buffer */
    char hexstr[2 * DATA_SIZE + 1];

    /* Return code from ECALL */
    int ret;
} Args;

#endif /* _ARGS_H */
