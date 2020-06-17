// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

struct __OE_IN6_ADDR
{
    union {
        uint8_t __s6_addr[16];
        uint16_t __s6_addr16[8];
        uint32_t __s6_addr32[4];
    } __in6_union;
};
