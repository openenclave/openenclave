// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/enclave.h>
#endif

#include <openenclave/bits/result.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <string.h>

#include "test.h"

#define TEST_BUFFER_SIZE 8

static bool buffer_is_set(unsigned char* buf, unsigned char value, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (buf[i] != value)
            return false;
    }
    return true;
}

void test_memcpy_s()
{
    unsigned char src[TEST_BUFFER_SIZE] = {0};
    unsigned char dst[TEST_BUFFER_SIZE] = {0};

    /* Test NULL buffers. If dst isn't null, it should be zeroed out. */
    OE_TEST(
        oe_memcpy_s(NULL, sizeof(dst), src, sizeof(src)) ==
        OE_INVALID_PARAMETER);

    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(
        oe_memcpy_s(dst, sizeof(dst), NULL, sizeof(src)) ==
        OE_INVALID_PARAMETER);
    OE_TEST(buffer_is_set(dst, 0, sizeof(dst)));

    /* Invalid size. dst should be zeroed out. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(
        oe_memcpy_s(dst, sizeof(dst), src, sizeof(src) + 1) ==
        OE_INVALID_PARAMETER);
    OE_TEST(buffer_is_set(dst, 0, sizeof(dst)));

    /* Overlapping buffers should fail. */
    memset(src, 1, sizeof(src));
    OE_TEST(oe_memcpy_s(src + 3, 4, src, 4) == OE_OVERLAPPED_COPY);
    OE_TEST(buffer_is_set(src + 3, 0, 4));

    memset(src, 1, sizeof(src));
    OE_TEST(oe_memcpy_s(src, 4, src + 3, 4) == OE_OVERLAPPED_COPY);
    OE_TEST(buffer_is_set(src, 0, 4));

    memset(src, 1, sizeof(src));
    OE_TEST(
        oe_memcpy_s(src, sizeof(src), src, sizeof(src)) == OE_OVERLAPPED_COPY);
    OE_TEST(buffer_is_set(src, 0, sizeof(src)));

    /* Test that copy works correctly if buffers don't overlap. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(oe_memcpy_s(dst, sizeof(dst), src, sizeof(src)) == OE_OK);
    OE_TEST(buffer_is_set(dst, 1, sizeof(dst)));

    /* Check if we only override the number of bytes specified. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(oe_memcpy_s(dst, sizeof(dst), src, 4) == OE_OK);
    OE_TEST(buffer_is_set(dst, 1, 4));
    OE_TEST(buffer_is_set(dst + 4, 2, sizeof(dst) - 4));
}

void test_memmove_s()
{
    unsigned char src[TEST_BUFFER_SIZE] = {0};
    unsigned char dst[TEST_BUFFER_SIZE] = {0};

    /* Test NULL buffers. If dst isn't null, it should be zeroed out. */
    OE_TEST(
        oe_memmove_s(NULL, sizeof(dst), src, sizeof(src)) ==
        OE_INVALID_PARAMETER);

    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(
        oe_memmove_s(dst, sizeof(dst), NULL, sizeof(src)) ==
        OE_INVALID_PARAMETER);
    OE_TEST(buffer_is_set(dst, 0, sizeof(dst)));

    /* Invalid size. dst should be zeroed out. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(
        oe_memmove_s(dst, sizeof(dst), src, sizeof(src) + 1) ==
        OE_INVALID_PARAMETER);
    OE_TEST(buffer_is_set(dst, 0, sizeof(dst)));

    /* Overlapping buffers should work. */
    memset(src, 1, 4);
    memset(src + 4, 2, sizeof(src) - 4);
    OE_TEST(oe_memmove_s(src + 3, 4, src, 4) == OE_OK);
    OE_TEST(buffer_is_set(src, 1, 7));
    OE_TEST(buffer_is_set(src + 7, 2, sizeof(src) - 7));

    memset(src, 1, 4);
    memset(src + 4, 2, sizeof(src) - 4);
    OE_TEST(oe_memmove_s(src, 4, src + 3, 4) == OE_OK);
    OE_TEST(buffer_is_set(src, 1, 1));
    OE_TEST(buffer_is_set(src + 1, 2, sizeof(src) - 1));

    memset(src, 1, sizeof(src));
    OE_TEST(oe_memmove_s(src, sizeof(src), src, sizeof(src)) == OE_OK);
    OE_TEST(buffer_is_set(src, 1, sizeof(src)));

    /* Regular non-overlapped mmemove. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(oe_memmove_s(dst, sizeof(dst), src, sizeof(src)) == OE_OK);
    OE_TEST(buffer_is_set(dst, 1, sizeof(dst)));

    /* Check if we only override dst_size bytes. */
    memset(src, 1, sizeof(src));
    memset(dst, 2, sizeof(dst));
    OE_TEST(oe_memmove_s(dst, sizeof(dst), src, 4) == OE_OK);
    OE_TEST(buffer_is_set(dst, 1, 4));
    OE_TEST(buffer_is_set(dst + 4, 2, sizeof(dst) - 4));
}

void test_strncpy_s()
{
    char src[TEST_BUFFER_SIZE] = {0};
    char dst[TEST_BUFFER_SIZE] = {0};

    /* Test NULL buffers. */
    OE_TEST(
        oe_strncpy_s(NULL, sizeof(dst), src, sizeof(src) - 1) ==
        OE_INVALID_PARAMETER);

    OE_TEST(
        oe_strncpy_s(dst, sizeof(dst), NULL, sizeof(src) - 1) ==
        OE_INVALID_PARAMETER);

    /* Test destination buffer is 0. */
    OE_TEST(oe_strncpy_s(dst, 0, src, sizeof(src) - 1) == OE_INVALID_PARAMETER);

    /* Check for overlapping copying. */
    char str1[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g', '\0'};
    OE_TEST(
        oe_strncpy_s(str1, sizeof(str1), str1 + 4, 4) == OE_OVERLAPPED_COPY);

    char str2[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g', '\0'};
    OE_TEST(
        oe_strncpy_s(str2, sizeof(str2), str2, sizeof(str2)) ==
        OE_OVERLAPPED_COPY);

    char str3[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g', '\0'};
    OE_TEST(
        oe_strncpy_s(str3 + 1, sizeof(str3) - 1, str3, 1) ==
        OE_OVERLAPPED_COPY);

    /* Check for cases where the destination buffer is too small. */
    char letters[sizeof(dst) + 1];
    memset(letters, 'a', sizeof(letters) - 1);
    letters[sizeof(letters) - 1] = '\0';

    OE_TEST(
        oe_strncpy_s(dst, sizeof(dst), letters, sizeof(letters)) ==
        OE_BUFFER_TOO_SMALL);
    OE_TEST(
        oe_strncpy_s(dst, sizeof(dst), letters, sizeof(letters) - 1) ==
        OE_BUFFER_TOO_SMALL);

    /* Check for valid strncpy cases. */
    OE_TEST(oe_strncpy_s(dst, 3, "aaaaa", 2) == OE_OK);
    OE_TEST(strcmp(dst, "aa") == 0);

    OE_TEST(oe_strncpy_s(dst, 6, "bbbbb", 5) == OE_OK);
    OE_TEST(strcmp(dst, "bbbbb") == 0);

    OE_TEST(oe_strncpy_s(dst, sizeof(dst), "ccccc", 10) == OE_OK);
    OE_TEST(strcmp(dst, "ccccc") == 0);
}

void test_strncat_s()
{
    char src[TEST_BUFFER_SIZE] = {0};
    char dst[TEST_BUFFER_SIZE] = {0};

    /* Test NULL buffers. */
    OE_TEST(
        oe_strncat_s(NULL, sizeof(dst), src, sizeof(src) - 1) ==
        OE_INVALID_PARAMETER);

    OE_TEST(
        oe_strncat_s(dst, sizeof(dst), NULL, sizeof(src) - 1) ==
        OE_INVALID_PARAMETER);

    /* Test destination buffer is 0. */
    OE_TEST(oe_strncat_s(dst, 0, src, sizeof(src) - 1) == OE_INVALID_PARAMETER);

    /* Check for overlapping copying. */
    char str1[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g', '\0'};
    OE_TEST(
        oe_strncat_s(str1, sizeof(str1), str1 + 4, 4) == OE_OVERLAPPED_COPY);

    char str2[] = {'a', 'b', 'c', '\0', 'd', 'e', 'f', 'g', '\0'};
    OE_TEST(
        oe_strncat_s(str2, sizeof(str2), str2, sizeof(str2)) ==
        OE_OVERLAPPED_COPY);

    /* Check for error if destination buffer is not null terminated. */
    memset(dst, 'a', sizeof(dst));
    memset(src, 'b', sizeof(src));
    src[sizeof(src) - 1] = '\0';

    OE_TEST(
        oe_strncat_s(dst, sizeof(dst), src, sizeof(src)) ==
        OE_BUFFER_TOO_SMALL);

    /* Check for error if destination buffer is too small. */
    memset(dst, 'a', sizeof(dst));
    dst[sizeof(dst) - 1] = '\0';
    OE_TEST(oe_strncat_s(dst, sizeof(dst), src, 1) == OE_BUFFER_TOO_SMALL);

    dst[0] = 'a';
    dst[1] = '\0';
    memset(src, 'b', sizeof(src) - 1);
    OE_TEST(
        oe_strncat_s(dst, sizeof(dst), src, sizeof(src) - 1) ==
        OE_BUFFER_TOO_SMALL);

    /* Check for valid strncat cases. */
    dst[0] = 'a';
    dst[1] = '\0';
    OE_TEST(oe_strncat_s(dst, sizeof(dst), "bbbb", 2) == OE_OK);
    OE_TEST(strcmp(dst, "abb") == 0);

    OE_TEST(oe_strncat_s(dst, sizeof(dst), "ccc", 3) == OE_OK);
    OE_TEST(strcmp(dst, "abbccc") == 0);

    OE_TEST(oe_strncat_s(dst, sizeof(dst), "d", 10) == OE_OK);
    OE_TEST(strcmp(dst, "abbcccd") == 0);
}

void test_memset_s()
{
    unsigned char buf[TEST_BUFFER_SIZE] = {0};

    /* Test invalid parameters */
    OE_TEST(
        oe_memset_s(NULL, sizeof(buf), 1, sizeof(buf) == OE_INVALID_PARAMETER));

    OE_TEST(oe_memset_s(buf, 4, 1, sizeof(buf)) == OE_INVALID_PARAMETER);
    OE_TEST(buffer_is_set(buf, 1, 4));

    /* Test valid cases of oe_memset_s. */
    OE_TEST(oe_memset_s(buf, sizeof(buf), 2, sizeof(buf)) == OE_OK);
    OE_TEST(buffer_is_set(buf, 2, sizeof(buf)));

    OE_TEST(oe_memset_s(buf, sizeof(buf), 3, 4) == OE_OK);
    OE_TEST(buffer_is_set(buf, 3, 4));
    OE_TEST(buffer_is_set(buf + 4, 2, sizeof(buf) - 4));
}
