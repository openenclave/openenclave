#include <openenclave/bits/heap.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

static OE_Heap _heap;

static int _InitHeap(OE_Heap* heap)
{
    void* base;
    size_t size = OE_PAGE_SIZE * 1024;

    /* Allocate aligned pages */
    if (!(base = memalign(OE_PAGE_SIZE, size)))
        return -1;

    return OE_HeapInit(heap, (uintptr_t)base, size);
}

int main(int argc, const char* argv[])
{
    if (_InitHeap(&_heap) != 0)
        assert(0);

    OE_HeapDump(&_heap);

    void* ptrs[16];

    for (size_t i = 0; i < 16; i++)
    {
        if (!(ptrs[i] = OE_HeapMap(&_heap, NULL, (i + 1) * 4096, 0, 0)))
            assert(0);
        printf("ptrs[%zu]=%016lx\n", i, (uintptr_t)ptrs[i]);
    }

    OE_HeapDump(&_heap);

    OE_HeapUnmap(&_heap, ptrs[0], 4096);

    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
