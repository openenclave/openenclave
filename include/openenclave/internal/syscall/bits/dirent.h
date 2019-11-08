// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

struct __OE_DIRENT
{
    uint64_t d_ino;
    oe_off_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[OE_NAME_MAX + 1];
};
