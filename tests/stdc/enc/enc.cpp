#include <openenclave/enclave.h>
#include <openenclave/bits/malloc.h>
#include <openenclave/bits/heap.h>
#include <assert.h>
#include <ctype.h>
#include <endian.h>
#include <errno.h>
#include <iso646.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>
#include "../args.h"

extern OE_Heap __oe_heap;

bool CheckMem(void* ptr, size_t n, uint8_t c)
{
    const uint8_t* p = (const uint8_t*)ptr;

    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != c)
            return false;
    }

    return true;
}

typedef struct _Chunk
{
    void* ptr;
    size_t size;
}
Chunk;

void TestAllocFree(
    size_t num_chunks, 
    size_t iterations, 
    size_t max_size)
{
    Chunk chunks[num_chunks];

    memset(chunks, 0, sizeof(chunks));

    for (size_t i = 0; i < iterations; i++)
    {
        size_t index = (rand() % num_chunks);

        if (chunks[index].ptr)
        {
            if (rand() % 2)
            {
                /* Perform free() */

                void* ptr = chunks[index].ptr;
                size_t size = chunks[index].size;
                uint8_t byte = size % 256;

                assert(CheckMem(ptr, size, byte));
                memset(ptr, 0xDD, size);
                free(ptr);
                chunks[index].ptr = NULL;
                chunks[index].size = 0;
            }
            else
            {
                /* Perform realloc() */

                void* old_ptr = chunks[index].ptr;
                size_t old_size = chunks[index].size;
                uint8_t old_byte = old_size % 256;
                void* new_ptr;
                size_t new_size = (rand() % max_size) + 1;
                uint8_t new_byte = new_size % 256;

                assert(CheckMem(old_ptr, old_size, old_byte));
                if (old_size > new_size)
                {
                    memset((uint8_t*)old_ptr + new_size, 
                        0xDD, old_size - new_size);
                }

                new_ptr = realloc(old_ptr, new_size);
                assert(new_ptr != NULL);
                memset(new_ptr, new_byte, new_size);

                chunks[index].ptr = new_ptr;
                chunks[index].size = new_size;
            }
        }
        else
        {
            /* Perform malloc() */

            size_t size = (rand() % max_size) + 1;
            uint8_t byte = size % 256;

            assert(size <= max_size);

            void* ptr = malloc(size);
            assert(ptr != NULL);
            memset(ptr, byte, size);

            chunks[index].ptr = ptr;
            chunks[index].size = size;
        }
    }

    /* Free any remaining chunks */
    for (size_t i = 0; i < num_chunks; i++)
    {
        void* ptr = chunks[i].ptr;
        size_t size = chunks[i].size;
        uint8_t byte = size % 256;

        assert(CheckMem(ptr, size, byte));
        memset(ptr, 0xDD, size);
        free(ptr);
    }
}

void Test_strtol()
{
    long x = strtol("1234", NULL, 10);
    assert(x == 1234);
}

void Test_strtoll()
{
    long x = strtoll("1234", NULL, 10);
    assert(x == 1234);
}

void Test_strtoul()
{
    unsigned long x = strtoul("1234", NULL, 10);
    assert(x == 1234);
}

void Test_strtoull()
{
    unsigned long long x = strtoull("1234", NULL, 10);
    assert(x == 1234);
}

void Test_strtof()
{
    double x = strtof("0.0", NULL);
    assert(x == 0);
}

void Test_strtod()
{
    double x = strtod("1.0", NULL);
    assert(x == 1.0);
}

void Test_strtold()
{
    long double x = strtold("1.0", NULL);
    assert(x == 1.0);
}

int compare(const void* p1, const void* p2)
{
    return *((int*)p1) - *((int*)p2);
}

void Test_qsort()
{
    int arr[] = { 100, 300, 200 };
    qsort(arr, OE_COUNTOF(arr), sizeof(int), compare);
    assert(arr[0] == 100);
    assert(arr[1] == 200);
    assert(arr[2] == 300);
}

void Test_bsearch()
{
    int arr[] = { 100, 300, 200 };
    void* key = &arr[1];
    void* r = bsearch(key, arr, OE_COUNTOF(arr), sizeof(int), compare);
    assert(r != NULL);
    assert(r == key);
}

void Test_abs()
{
    assert(abs(-1) == 1);
    assert(abs(1) == 1);
    assert(abs(0) == 0);
}

void Test_labs()
{
    assert(labs(-1) == 1);
    assert(labs(1) == 1);
    assert(labs(0) == 0);
}

void Test_llabs()
{
    assert(llabs(-1) == 1);
    assert(llabs(1) == 1);
    assert(llabs(0) == 0);
}

#if 0
void Test_div()
{
    div_t r = div(5, 3);
    assert(r.quot == 1);
    assert(r.rem == 2);
}
#endif

int TestSetjmp()
{
    jmp_buf buf;

    int rc = setjmp(buf);

    if (rc == 999)
        return rc;

    longjmp(buf, 999);
    return 0;
}

void Test_atox()
{
    assert(atoi("100") == 100);
    assert(atol("100") == 100L);
    assert(atoll("100") == 100LL);
    assert(atof("1.0") == 1.0);
}

static bool _calledAllocationFailureCallback;

static void _AllocationFailureCallback(
    const char* file, 
    size_t line, 
    const char* func, 
    size_t size)
{
#if 0
    printf("OE_AllocationFailureCallback(): %s(%zu): %s: %zu\n",
        file, line, func, size);
#endif
    _calledAllocationFailureCallback = true;
}

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    OE_SetAllocationFailureCallback(_AllocationFailureCallback);

    strcpy(args->buf1, "AAA");
    strcat(args->buf1, "BBB");
    strcat(args->buf1, "CCC");

    {
        char* s = strdup("strdup");

        if (s && strcmp(s, "strdup") == 0 && strlen(s) == 6)
        {
            if (memcmp(s, "strdup", 6) == 0)
                args->strdupOk = 1;
        }
        else
            args->strdupOk = 0;

        free(s);
    }

    snprintf(args->buf2, sizeof(args->buf2), "%s=%d", "value", 100);

    Test_strtol();
    Test_strtoll();
    Test_strtoul();
    Test_strtoull();
    Test_strtof();
    Test_strtod();
    Test_strtold();
    Test_qsort();
    Test_bsearch();
    Test_abs();
    Test_labs();
    Test_llabs();
#if 0
    Test_div();
#endif
    Test_atox();

    struct timeval tv = { 0, 0 };
    assert(gettimeofday(&tv, NULL) == 0);

    struct timespec ts;
    clock_gettime(0, &ts);

    /* Sleep for a second */
    timespec req = { 1, 0 };
    timespec rem;
    nanosleep(&req, &rem);

    assert(TestSetjmp() == 999);

    /* Cause malloc() to fail */
    void* p = malloc(1024 * 1024 * 1024);
    assert(p == NULL);
    assert(_calledAllocationFailureCallback);

    /* Test random allocations and frees */
    {
        /* Enable sanity checking */
        OE_HeapSetSanity(&__oe_heap, true);

        /* Perform tests */
        const size_t iterations = 10000;
        TestAllocFree(4096, iterations, 16);
        TestAllocFree(4096, iterations, 256);
        TestAllocFree(4096, iterations, 4096);
        TestAllocFree(256, iterations, 64*4096);

        /* Check coverage */
        for (size_t i = 0; i < OE_HEAP_COVERAGE_N; i++)
        {
            /* Ignore OE_HEAP_COVERAGE_12 (it occurs only when remapping a 
             * memory area to the same size).
             */
            if (!__oe_heap.coverage[i] && i != OE_HEAP_COVERAGE_12)
            {
                fprintf(stderr, "*** not covered: OE_HEAP_COVERAGE_%zu\n", i);
                assert(0);
            }
        }

        /* Recheck sanity */
        assert(OE_HeapSane(&__oe_heap));

        /* Fail if VAD list is not empty */
        if (__oe_heap.vad_list)
        {
            fprintf(stderr, "*** VAD list not empty\n");
            assert(0);
        }
    }

    /* Test allocation of all sizes */
    {
        /* Enable sanity checking */
        OE_HeapSetSanity(&__oe_heap, true);

        for (size_t i = 1; i < 1024*1024; i += 4096)
        {
            void* ptr = malloc(i);

            if (!ptr)
                break;

            free(ptr);
        }

        /* Recheck sanity */
        assert(OE_HeapSane(&__oe_heap));

        /* Fail if VAD list is not empty */
        if (__oe_heap.vad_list)
        {
            fprintf(stderr, "*** VAD list not empty\n");
            assert(0);
        }
    }

#if 0
    printf("UINT_MIN=%u UINT_MAX=%u\n", 0, UINT_MAX);
    printf("INT_MIN=%d INT_MAX=%d\n", INT_MIN, INT_MAX);
    printf("LONG_MIN=%ld LONG_MAX=%ld\n", LONG_MIN, LONG_MAX);
#endif
}
