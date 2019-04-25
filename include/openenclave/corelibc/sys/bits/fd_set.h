// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef struct
{
    unsigned long fds_bits[OE_FD_SETSIZE / 8 / sizeof(long)];
} _OE_TYPEDEF_FD_SET;
