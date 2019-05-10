// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

typedef struct
{
    unsigned long fds_bits[OE_FD_SETSIZE / 8 / sizeof(long)];
} __OE_FD_SET;
