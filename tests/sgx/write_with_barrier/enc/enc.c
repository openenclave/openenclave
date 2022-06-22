// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include "write_with_barrier_t.h"

#include <stdio.h>

static void _reset_buffer(void* dest, size_t count)
{
    const uint8_t zeroized_buffer[1008] = {0};

    OE_TEST(oe_memset_with_barrier(dest, 0, count) == dest);

    OE_TEST(
        memcmp((const void*)dest, (const void*)zeroized_buffer, count) == 0);
}

static void _reset_buffer_s(void* dest, size_t dest_count, size_t num_bytes)
{
    const uint8_t zeroized_buffer[1008] = {0};

    OE_TEST(oe_memset_s_with_barrier(dest, dest_count, 0, num_bytes) == OE_OK);

    OE_TEST(
        memcmp((const void*)dest, (const void*)zeroized_buffer, num_bytes) ==
        0);
}

static void _copy_and_compare(void* dest, const void* src, size_t count)
{
    OE_TEST(oe_memcpy_with_barrier(dest, src, count) == dest);

    OE_TEST(memcmp((const void*)dest, src, count) == 0);
}

static void _copy_s_and_compare(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes)
{
    OE_TEST(
        oe_memcpy_s_with_barrier(dest, dest_count, src, num_bytes) == OE_OK);

    OE_TEST(memcmp((const void*)dest, (const void*)src, num_bytes) == 0);
}

static void _move_and_compare(void* dest, const void* src, size_t count)
{
    OE_TEST(oe_memmove_with_barrier(dest, src, count) == dest);

    OE_TEST(memcmp((const void*)dest, src, count) == 0);
}

static void _move_s_and_compare(
    void* dest,
    size_t dest_count,
    const void* src,
    size_t num_bytes)
{
    OE_TEST(
        oe_memmove_s_with_barrier(dest, dest_count, src, num_bytes) == OE_OK);

    OE_TEST(memcmp((const void*)dest, (const void*)src, num_bytes) == 0);
}

void enc_write_with_barrier()
{
    {
        uint64_t value = 0;

        /* Test 8-byte write */
        OE_WRITE_VALUE_WITH_BARRIER(&value, (uint64_t)0xdddddddddddddddd);
        OE_TEST(value == 0xdddddddddddddddd);

        /* Test 4-byte write */
        OE_WRITE_VALUE_WITH_BARRIER(&value, (uint32_t)0xcccccccc);
        OE_TEST((uint32_t)value == 0xcccccccc);
        OE_TEST(value == 0xddddddddcccccccc);

        /* Test 2-byte write */
        OE_WRITE_VALUE_WITH_BARRIER(&value, (uint16_t)0xbbbb);
        OE_TEST((uint16_t)value == 0xbbbb);
        OE_TEST(value == 0xddddddddccccbbbb);

        /* Test 1-byte write */
        OE_WRITE_VALUE_WITH_BARRIER(&value, (uint8_t)0xaa);
        OE_TEST((uint8_t)value == 0xaa);
        OE_TEST(value == 0xddddddddccccbbaa);

        OE_WRITE_VALUE_WITH_BARRIER(&value, (uint64_t)0);
        OE_TEST(value == 0);
    }

    {
        const size_t buffer_size = 1000;
        uint8_t buffer[1008] __attribute__((aligned(8))) = {0};
        uint8_t expected_buffer1[1008];
        uint8_t expected_buffer2[1008];

        memset(expected_buffer1, 'a', sizeof(expected_buffer1));
        memset(expected_buffer2, 'b', sizeof(expected_buffer2));

        OE_TEST(((uint64_t)buffer % 8) == 0);
        OE_TEST(((uint64_t)expected_buffer1 % 8) == 0);
        OE_TEST(((uint64_t)expected_buffer2 % 8) == 0);

        /* Test early-return cases */
        OE_TEST(
            oe_memcpy_with_barrier(buffer, buffer, sizeof(buffer)) == buffer);
        OE_TEST(oe_memcpy_with_barrier(buffer, buffer, 0) == buffer);
        OE_TEST(oe_memset_with_barrier(buffer, 0, 0) == buffer);

        /* Test memcpy with 8-byte-aligned destination and non-8-byte-aligned
         * source */
        for (size_t offset = 0; offset < 8; offset++)
        {
            _copy_and_compare(buffer, expected_buffer1 + offset, buffer_size);

            _reset_buffer(buffer, sizeof(buffer));

            _move_and_compare(buffer, expected_buffer1 + offset, buffer_size);

            _reset_buffer(buffer, sizeof(buffer));

            _copy_s_and_compare(
                buffer, sizeof(buffer), expected_buffer1 + offset, buffer_size);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));

            _move_s_and_compare(
                buffer, sizeof(buffer), expected_buffer1 + offset, buffer_size);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));
        }

        /* Test memcpy with 8-byte-aligned addresses and size is not multiples
         * of 8 */
        for (size_t offset = 0; offset < 8; offset++)
        {
            _copy_and_compare(buffer, expected_buffer1, buffer_size + offset);

            _reset_buffer(buffer, sizeof(buffer));

            _move_and_compare(buffer, expected_buffer1, buffer_size + offset);

            _reset_buffer(buffer, sizeof(buffer));

            _copy_s_and_compare(
                buffer, sizeof(buffer), expected_buffer1, buffer_size + offset);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));

            _move_s_and_compare(
                buffer, sizeof(buffer), expected_buffer1, buffer_size + offset);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));
        }

        /* Test with non-8-byte-aligned destination */
        for (size_t offset = 0; offset < 8; offset++)
        {
            _copy_and_compare(
                (void*)((uint64_t)buffer + offset),
                expected_buffer2,
                buffer_size);

            _reset_buffer(buffer, sizeof(buffer));

            _move_and_compare(
                (void*)((uint64_t)buffer + offset),
                expected_buffer2,
                buffer_size);

            _reset_buffer(buffer, sizeof(buffer));

            _copy_s_and_compare(
                (void*)((uint64_t)buffer + offset),
                sizeof(buffer),
                expected_buffer2,
                buffer_size);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));

            _move_s_and_compare(
                (void*)((uint64_t)buffer + offset),
                sizeof(buffer),
                expected_buffer2,
                buffer_size);

            _reset_buffer_s(buffer, sizeof(buffer), sizeof(buffer));
        }

        /* Test memmove with overlapping enclave memory */
        uint8_t expected_buffer3[1000];
        uint8_t expected_buffer4[1000];

        memset(expected_buffer3, 'a', sizeof(expected_buffer3));
        memset(expected_buffer3, 'c', 100);

        memset(expected_buffer4, 'a', sizeof(expected_buffer4));
        memset(expected_buffer4 + 900, 'c', 100);

        memset(buffer, 'c', sizeof(buffer));
        memset(buffer + 500, 'a', 500);
        oe_memmove_with_barrier(buffer, buffer + 400, 500);
        OE_TEST(
            memcmp((const void*)buffer, (const void*)expected_buffer3, 1000) ==
            0);

        memset(buffer, 'c', sizeof(buffer));
        memset(buffer + 500, 'a', 500);
        OE_TEST(
            oe_memmove_s_with_barrier(
                buffer, sizeof(buffer), buffer + 400, 500) == OE_OK);
        OE_TEST(
            memcmp((const void*)buffer, (const void*)expected_buffer3, 1000) ==
            0);

        memset(buffer, 'c', sizeof(buffer));
        memset(buffer, 'a', 500);
        oe_memmove_with_barrier(buffer + 400, buffer, 500);
        OE_TEST(
            memcmp((const void*)buffer, (const void*)expected_buffer4, 1000) ==
            0);

        memset(buffer, 'c', sizeof(buffer));
        memset(buffer, 'a', 500);
        OE_TEST(
            oe_memmove_s_with_barrier(
                buffer + 400, sizeof(buffer) - 400, buffer, 500) == OE_OK);
        OE_TEST(
            memcmp((const void*)buffer, (const void*)expected_buffer4, 1000) ==
            0);

        /* Test memmove with overlapping host memory */
        const size_t host_buffer_size = 1000;
        uint8_t* host_buffer;

        host_buffer = oe_host_malloc(host_buffer_size);
        OE_TEST(((uint64_t)host_buffer % 8) == 0);

        memset(host_buffer, 'c', host_buffer_size);
        memset(host_buffer + 500, 'a', 500);
        oe_memmove_with_barrier(host_buffer, host_buffer + 400, 500);
        OE_TEST(
            memcmp(
                (const void*)host_buffer,
                (const void*)expected_buffer3,
                1000) == 0);

        memset(host_buffer, 'c', host_buffer_size);
        memset(host_buffer + 500, 'a', 500);
        OE_TEST(
            oe_memmove_s_with_barrier(
                host_buffer, host_buffer_size, host_buffer + 400, 500) ==
            OE_OK);
        OE_TEST(
            memcmp(
                (const void*)host_buffer,
                (const void*)expected_buffer3,
                1000) == 0);

        memset(host_buffer, 'c', host_buffer_size);
        memset(host_buffer, 'a', 500);
        oe_memmove_with_barrier(host_buffer + 400, host_buffer, 500);
        OE_TEST(
            memcmp(
                (const void*)host_buffer,
                (const void*)expected_buffer4,
                1000) == 0);

        memset(host_buffer, 'c', host_buffer_size);
        memset(host_buffer, 'a', 500);
        OE_TEST(
            oe_memmove_s_with_barrier(
                host_buffer + 400, host_buffer_size - 400, host_buffer, 500) ==
            OE_OK);
        OE_TEST(
            memcmp(
                (const void*)host_buffer,
                (const void*)expected_buffer4,
                1000) == 0);

        oe_host_free(host_buffer);
    }

    /* Negative tests */
    {
        uint8_t buffer[1000] __attribute__((aligned(8)));
        uint8_t init_buffer[1000];
        uint8_t expected_buffer[1000];
        const uint8_t zeroized_buffer[1000] = {0};

        memset(buffer, 'x', sizeof(buffer));
        memset(init_buffer, 'x', sizeof(expected_buffer));
        memset(expected_buffer, 'a', sizeof(expected_buffer));

        /* oe_memcpy_s_with_barrier */

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                NULL, sizeof(buffer), expected_buffer, sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer,
                OE_UINT64_MAX,
                expected_buffer,
                sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer, sizeof(buffer), NULL, sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer, sizeof(buffer), expected_buffer, OE_UINT64_MAX),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer, sizeof(buffer), expected_buffer, sizeof(buffer) + 1),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer, sizeof(buffer), buffer + 1, sizeof(buffer)),
            OE_OVERLAPPED_COPY);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memcpy_s_with_barrier(
                buffer, sizeof(buffer), buffer - 1, sizeof(buffer)),
            OE_OVERLAPPED_COPY);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        /* oe_memmove_s_with_barrier */

        OE_EXPECT(
            oe_memmove_s_with_barrier(
                NULL, sizeof(buffer), expected_buffer, sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memmove_s_with_barrier(
                buffer,
                OE_UINT64_MAX,
                expected_buffer,
                sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memmove_s_with_barrier(
                buffer, sizeof(buffer), NULL, sizeof(expected_buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memmove_s_with_barrier(
                buffer, sizeof(buffer), expected_buffer, OE_UINT64_MAX),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        OE_EXPECT(
            oe_memmove_s_with_barrier(
                buffer, sizeof(buffer), expected_buffer, sizeof(buffer) + 1),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is zeroized */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)zeroized_buffer,
                sizeof(buffer)) == 0);

        /* Reset the buffer */
        memset(buffer, 'x', sizeof(buffer));

        /* oe_memset_with_barrier */

        OE_EXPECT(
            oe_memset_s_with_barrier(NULL, sizeof(buffer), 'a', sizeof(buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memset_s_with_barrier(
                buffer, OE_UINT64_MAX, 'a', sizeof(buffer)),
            OE_INVALID_PARAMETER);

        /* Expected the buffer is unchanged */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)init_buffer,
                sizeof(buffer)) == 0);

        OE_EXPECT(
            oe_memset_s_with_barrier(
                buffer, sizeof(buffer) - 10, 'a', sizeof(buffer)),
            OE_INVALID_PARAMETER);

        /* Expected size(buffer) - 10 bytes to be set */
        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)expected_buffer,
                sizeof(buffer) - 10) == 0);

        OE_TEST(
            memcmp(
                (const void*)buffer,
                (const void*)expected_buffer,
                sizeof(buffer)) != 0);
    }
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
