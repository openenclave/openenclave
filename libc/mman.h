// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <sys/mman.h>

void* oe_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset);

int oe_munmap(void* addr, uint64_t length);

typedef struct _mapping
{
    uint64_t start;
    uint64_t end;
    uint8_t* status_vector;
    struct _mapping* next;
} oe_mapping_t;

oe_mapping_t* oe_test_get_mappings(void);
