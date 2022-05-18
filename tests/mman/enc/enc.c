// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/tests.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include "../../../libc/mman.h"
#include "mman_t.h"
#include "openenclave/bits/defs.h"

const uint64_t chunk_size = 1024;

static void _test_basic()
{
    // Test whether memory can be mmaped and unmapped.
    uint8_t* ptr = (uint8_t*)mmap(
        NULL,
        chunk_size,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    OE_TEST(ptr != MAP_FAILED);
    OE_TEST(errno == 0);

    // Test that memory is zeroed out.
    for (uint64_t i = 0; i < chunk_size; ++i)
        OE_TEST(ptr[i] == 0);

    OE_TEST(munmap(ptr, chunk_size) == 0);
    OE_TEST(errno == 0);
    OE_TEST(oe_test_get_mappings() == NULL);
}

static void _test_partial_unmapping(void)
{
    uint64_t p1_length = 5 * OE_PAGE_SIZE;
    uint64_t p1_start = (uint64_t)mmap(
        NULL,
        p1_length - 477,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    uint64_t p1_end = p1_start + p1_length;

    oe_mapping_t* m = oe_test_get_mappings();
    OE_TEST(m->start == p1_start);
    OE_TEST(m->end == p1_end);

    uint64_t p2_length = 3 * OE_PAGE_SIZE;
    uint64_t p2_start = (uint64_t)mmap(
        NULL,
        p2_length - 2048,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0);
    uint64_t p2_end = p2_start + p2_length;
    m = oe_test_get_mappings();
    OE_TEST(m->start == p2_start);
    OE_TEST(m->end == p2_end);

    // Swap p1 and p2 if p2 lies before p1.
    bool swapped = false;
    if (p2_start < p1_start)
    {
        uint64_t t = p1_start;
        p1_start = p2_start;
        p2_start = t;

        t = p1_end;
        p1_end = p2_end;
        p2_end = t;
        swapped = true;
    }

    // Do an unmap that starts within p1 and ends within p2.
    uint64_t start = p1_end - OE_PAGE_SIZE;
    uint64_t end = p2_end - OE_PAGE_SIZE;
    OE_TEST(munmap((void*)start, end - start) == 0);
    OE_TEST(errno == 0);

    // Partial unmapping only changes the status vectors and not the bounds.
    m = oe_test_get_mappings();
    if (swapped)
    {
        OE_TEST(m->start == p1_start);
        OE_TEST(m->end == p1_end);
        m = m->next;
        OE_TEST(m->start == p2_start);
        OE_TEST(m->end == p2_end);
    }
    else
    {
        OE_TEST(m->start == p2_start);
        OE_TEST(m->end == p2_end);
        m = m->next;
        OE_TEST(m->start == p1_start);
        OE_TEST(m->end == p1_end);
    }

    // Do another partial unmap.
    start -= OE_PAGE_SIZE;
    OE_TEST(munmap((void*)start, end - start) == 0);
    OE_TEST(errno == 0);
    m = oe_test_get_mappings();
    if (swapped)
    {
        OE_TEST(m->start == p1_start);
        OE_TEST(m->end == p1_end);
        m = m->next;
        OE_TEST(m->start == p2_start);
        OE_TEST(m->end == p2_end);
    }
    else
    {
        OE_TEST(m->start == p2_start);
        OE_TEST(m->end == p2_end);
        m = m->next;
        OE_TEST(m->start == p1_start);
        OE_TEST(m->end == p1_end);
    }

    // Do an unmap till the start.
    // This ought to delete one mapping completely.
    OE_TEST(munmap((void*)OE_PAGE_SIZE, start - OE_PAGE_SIZE) == 0);
    OE_TEST(errno == 0);
    m = oe_test_get_mappings();
    OE_TEST(m->next == NULL);

    // Do another unmapping that spans entire enclave memory.
    // This ought to get rid of all mappings.
    for (size_t i = 1; i < 20; ++i)
    {
        OE_TEST(
            mmap(NULL, i * 1, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) !=
            MAP_FAILED);
        OE_TEST(errno == 0);
    }
    OE_TEST(munmap(0, (1L << 62)) == 0);
    OE_TEST(errno == 0);
    OE_TEST(oe_test_get_mappings() == NULL);

    // Test unmapping a mapping in small chunks.
    start = (uint64_t)mmap(
        NULL, 3 * OE_PAGE_SIZE, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    OE_TEST(oe_test_get_mappings() != NULL);

    OE_TEST(munmap((void*)(start + OE_PAGE_SIZE), 1) == 0);
    OE_TEST(oe_test_get_mappings() != NULL);
    OE_TEST(munmap((void*)(start + 2 * OE_PAGE_SIZE), 1) == 0);
    OE_TEST(oe_test_get_mappings() != NULL);
    OE_TEST(munmap((void*)start, 1) == 0);
    OE_TEST(oe_test_get_mappings() == NULL);
}

static void _test_mmap_params(void)
{
    // Non zero addr should be ignored.
    OE_TEST(
        mmap(
            (void*)1,
            chunk_size,
            PROT_READ,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0) != MAP_FAILED);
    OE_TEST(errno == 0);

    // Zero length should fail.
    OE_TEST(
        mmap(NULL, 0, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    // Large mmap should fail.
    // Note: snmalloc crashes with a shift greater than 49.
    OE_TEST(
        mmap(NULL, (1L << 49), PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == ENOMEM);

    OE_TEST(
        mmap(NULL, (1L << 32), PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == ENOMEM);

    // Test various prots.
    OE_TEST(
        mmap(NULL, chunk_size, 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    OE_TEST(
        mmap(NULL, chunk_size, PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    errno = 0;
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) !=
        MAP_FAILED);
    OE_TEST(errno == 0);

    // Check that mmap of multiple of chunk size works.
    OE_TEST(
        mmap(
            NULL,
            5 * chunk_size,
            PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0) != MAP_FAILED);
    OE_TEST(errno == 0);

    OE_TEST(
        mmap(
            NULL,
            chunk_size,
            PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE,
            -1,
            0) != MAP_FAILED);
    OE_TEST(errno == 0);

    // Test various flags.
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ | PROT_WRITE, 0, -1, 0) == MAP_FAILED);
    OE_TEST(errno == EINVAL);

    errno = 0;
    // One of MAP_SHARED, MAP_SHARED_VALIDATE, MAP_PRIVATE must be used.
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ | PROT_WRITE, MAP_SHARED, -1, 0) !=
        MAP_FAILED);
    OE_TEST(errno == 0);

    OE_TEST(
        mmap(
            NULL,
            chunk_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED_VALIDATE,
            -1,
            0) != MAP_FAILED);
    OE_TEST(errno == 0);

    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, -1, 0) !=
        MAP_FAILED);
    OE_TEST(errno == 0);

    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    errno = 0;
    // Test unsupported flags.
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0) !=
        MAP_FAILED);
    OE_TEST(errno == 0);

    int unsupported[] = {
#ifdef MAP_32BIT
        MAP_32BIT,
#endif
        MAP_FIXED,
        MAP_FIXED_NOREPLACE,
        MAP_GROWSDOWN,
        MAP_HUGETLB,
        MAP_HUGE_2MB,
        MAP_HUGE_1GB,
        MAP_LOCKED};
    for (size_t i = 0; i < OE_COUNTOF(unsupported); ++i)
    {
        errno = 0;
        OE_TEST(
            mmap(
                NULL,
                chunk_size,
                PROT_READ,
                unsupported[i] | MAP_PRIVATE,
                0,
                0) == MAP_FAILED);
        OE_TEST(errno == EINVAL);
    }

    int ignored[] = {
        MAP_DENYWRITE,
        MAP_EXECUTABLE,
        MAP_FILE,
        MAP_NONBLOCK,
        MAP_NORESERVE,
        MAP_POPULATE,
        MAP_STACK,
        MAP_SYNC};
    for (size_t i = 0; i < OE_COUNTOF(ignored); ++i)
    {
        errno = 0;
        OE_TEST(
            mmap(NULL, chunk_size, PROT_READ, ignored[i] | MAP_PRIVATE, 0, 0) !=
            MAP_FAILED);
        OE_TEST(errno == 0);
    }

    // fd is ignored.
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0) !=
        MAP_FAILED);
    OE_TEST(errno == 0);

    OE_TEST(
        mmap(
            NULL,
            chunk_size,
            PROT_READ,
            MAP_ANONYMOUS | MAP_PRIVATE,
            1234,
            0) != MAP_FAILED);
    OE_TEST(errno == 0);

    // offset must be zero.
    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, -1) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    OE_TEST(
        mmap(NULL, chunk_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 1) ==
        MAP_FAILED);
    OE_TEST(errno == EINVAL);

    // All the mapping ought to be autoamatically cleared during atexit.
    // If that doens't happen, the test will fail due to memory leak.
}

static void _test_unmap_params(void)
{
    // Test various parameters for unmap.
    void* ptrs[] = {
        0,
        (void*)OE_PAGE_SIZE, // It is valid to unmap pages that are not mapped.
    };

    uint64_t lengths[] = {0, 47, OE_PAGE_SIZE, 12345, (1L << 56)};

    for (size_t i = 0; i < OE_COUNTOF(ptrs); ++i)
    {
        for (size_t j = 0; j < OE_COUNTOF(lengths); ++j)
        {
            errno = -1;
            OE_TEST(munmap(ptrs[i], lengths[j]) == 0);
            OE_TEST(errno == 0);
        }
    }

    // addr must be multiple of page size.
    OE_TEST(munmap((void*)chunk_size, OE_PAGE_SIZE) != 0);
    OE_TEST(errno == EINVAL);
}

int enc_main()
{
    _test_basic();
    _test_partial_unmapping();
    _test_mmap_params();
    _test_unmap_params();
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
