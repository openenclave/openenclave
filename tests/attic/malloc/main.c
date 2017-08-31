#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oeinternal/malloc.h>
#include <assert.h>

#define MEM_REALLOC OE_Realloc
#define MEM_FREE OE_Free
#include <oeinternal/mem.h>

static uint64_t _heap[16*1024*1024];

#if 0
static size_t _Round(size_t x, size_t m)
{
    return (x + m - 1) / m * m;
}
#endif

static void _DumpStats()
{
    OE_MallocStats stats;
    OE_GetMallocStats(&stats);

    printf("=== _DumpStats()\n");
    printf("stats.freeListSize: %zu\n", stats.freeListSize);
    printf("stats.heapSize: %zu\n", stats.heapSize);
    printf("stats.heapUsed: %zu\n", stats.heapUsed);
    printf("stats.heapAvailable: %zu\n", stats.heapAvailable);
    printf("stats.heapUsage: %f%%\n", stats.heapUsage);
    printf("stats.numMallocs: %zu\n", stats.numMallocs);
    printf("stats.numFrees: %zu\n", stats.numFrees);
    printf("\n");
}

void Test1()
{
    const size_t N = 250;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        void* ptr = OE_Malloc(i);
        assert(ptr != NULL);
        memset(ptr, 0xAA, i);
        ptrs[i] = ptr;
    }

    for (size_t i = 1; i < N; i++)
    {
        OE_Free(ptrs[i]);
    }

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test1()\n");
}

void Test2()
{
    const size_t N = 250;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        size_t r = rand() % 10;
        void* ptr = OE_Memalign(1 << r, i);
        assert(ptr != NULL);
        ptrs[i] = ptr;
    }

    for (size_t i = 1; i < N; i++)
    {
        OE_Free(ptrs[i]);
    }

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test2()\n");
}

void Test3()
{
    const size_t N = 250;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        void* ptr = OE_Malloc(i);
        assert(ptr != NULL);
        memset(ptr, 0xAA, i);
        ptrs[i] = ptr;
    }

    for (size_t i = N-1; i > 0; i--)
        OE_Free(ptrs[i]);

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test3()\n");
}

void Test4()
{
    const size_t N = 250;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        size_t r = rand() % 10;
        void* ptr = OE_Memalign(1 << r, i);
        assert(ptr != NULL);
        ptrs[i] = ptr;
    }

    for (size_t i = 1; i < N; i += 2)
        OE_Free(ptrs[i]);

    for (size_t i = 2; i < N; i += 2)
        OE_Free(ptrs[i]);

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test4()\n");
}

void Test5()
{
    const size_t N = 250;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        size_t r = rand() % 10;
        void* ptr = OE_Memalign(1 << r, i);
        assert(ptr != NULL);
        ptrs[i] = ptr;
    }

    for (size_t i = 1; i < N; i += 2)
        OE_Free(ptrs[i]);

    {
        const size_t M = 10;
        void* ptrs2[M];

        for (size_t i = 1; i < M; i++)
        {
            size_t r = rand() % 10;
            void* ptr = OE_Memalign(1 << r, i);
            assert(ptr != NULL);
            ptrs2[i] = ptr;
        }

        for (size_t i = 1; i < M; i++)
            OE_Free(ptrs2[i]);
    }

    for (size_t i = 2; i < N; i += 2)
        OE_Free(ptrs[i]);

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test5()\n");
}

void Test6()
{
    const size_t N = 1000;
    void* ptrs[N];

    for (size_t i = 1; i < N; i++)
    {
        void* ptr = OE_Malloc(i);
        assert(ptr != NULL);
        memset(ptr, 0xAA, i);
        ptrs[i] = ptr;
    }

    for (size_t i = 1; i < N; i++)
    {
        OE_Free(ptrs[i]);
    }

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passes Test6()\n");
}

void Test7()
{
    static void* blocks[100000];
    const size_t nblocks = OE_COUNTOF(blocks);
    size_t nallocs = 0;
    size_t nfrees = 0;

    memset(blocks, 0, sizeof(blocks));

    /* Allocate half of the blocks now */
    for (size_t i = 0; i < nblocks; i++)
    {
        size_t index = (rand() % nblocks);

        if (blocks[index])
        {
            //printf("FREE{%p}\n", blocks[index]);
            OE_Free(blocks[index]);
            blocks[index] = NULL;
            nfrees++;
        }
        else
        {
            size_t r = ((rand() % 1024) + 1);

            if (!(blocks[index] = OE_Malloc(r)))
                assert(0);

            memset(blocks[index], 0xAA, r);

            nallocs++;
        }
    }

    /* Return any unused memory */
    for (size_t i = 0; i < nblocks; i++)
    {
        if (blocks[i])
        {
            OE_Free(blocks[i]);
            blocks[i] = NULL;
            nfrees++;
        }
    }

    printf("=== passed Test7()\n");
}

void Test8()
{
    char* ptr;

    assert(ptr = OE_Realloc(NULL, 5));
    strcpy(ptr, "abcd");
    assert(strcmp(ptr, "abcd") == 0);

    assert(ptr = OE_Realloc(ptr, 8));
    strcat(ptr, "efg");
    assert(strcmp(ptr, "abcdefg") == 0);

    assert(ptr = OE_Realloc(ptr, 12));
    strcat(ptr, "hijk");
    assert(strcmp(ptr, "abcdefghijk") == 0);

    assert(ptr = OE_Realloc(ptr, 17));
    strcat(ptr, "lmnop");
    assert(strcmp(ptr, "abcdefghijklmnop") == 0);

    assert(ptr = OE_Realloc(ptr, 23));
    strcat(ptr, "qrstuv");
    assert(strcmp(ptr, "abcdefghijklmnopqrstuv") == 0);

    assert(ptr = OE_Realloc(ptr, 27));
    strcat(ptr, "wxyz");
    assert(strcmp(ptr, "abcdefghijklmnopqrstuvwxyz") == 0);

    assert(ptr = OE_Realloc(ptr, 27+32));
    strcat(ptr, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    assert(strcmp(ptr, 
        "abcdefghijklmnopqrstuvwxyz"
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx") == 0);

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    assert(ptr = OE_Realloc(ptr, 27));
    assert(memcmp(ptr, "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    assert(ptr = OE_Realloc(ptr, 4));
    assert(memcmp(ptr, "abcd", 4) == 0);

    OE_Free(ptr);

    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);

    printf("=== passed Test8()\n");
}

void Test9()
{
    mem_t mem = MEM_DYNAMIC_INIT;

    for (size_t i = 0; i < 4096; i++)
        mem_catc(&mem, i % 256);

    const uint8_t* ptr = (const uint8_t*)mem_ptr(&mem);

    for (size_t i = 0; i < 4096; i++)
        assert(ptr[i] == i % 256);

    mem_free(&mem);

    printf("=== passed Test9()\n");
}

int main(int argc, const char* argv[])
{
    OE_InitMalloc(_heap, sizeof(_heap));
    Test1();
    Test2();
    Test3();
    Test4();
    Test5();
    Test6();
    Test7();
    Test8();
    Test9();

    OE_MallocStats stats;
    OE_GetMallocStats(&stats);
    assert(stats.freeListSize == 1);
    assert(stats.numMallocs == stats.numFrees);

    printf("=== passed all tests (%s)\n", argv[0]);

    _DumpStats();

    return 0;
}
