#include <openenclave/bits/heap.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

static size_t PGSZ = OE_PAGE_SIZE;

static int _InitHeap(OE_Heap* heap, size_t size)
{
    void* base;

    /* Allocate aligned pages */
    if (!(base = memalign(OE_PAGE_SIZE, size)))
        return -1;

    return OE_HeapInit(heap, (uintptr_t)base, size);
}

static size_t _CountVADs(const OE_VAD* list)
{
    const OE_VAD* p;
    size_t count = 0;

    for (p = list; p; p = p->next)
        count++;

    return count;
}

static bool _IsSorted(const OE_VAD* list)
{
    const OE_VAD* p;
    const OE_VAD* prev = NULL;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev && !(prev->addr < p->addr))
            return false;
    }

    return true;
}

/* Check that there are no gaps between the VADs in the list */
static bool _IsFlush(const OE_Heap* heap, const OE_VAD* list)
{
    const OE_VAD* p;
    const OE_VAD* prev = NULL;

    if (!list)
        return true;

    if (heap->mapped_top != list->addr)
        return false;

    for (p = list; p; prev = p, p = p->next)
    {
        if (prev)
        {
            if (prev->addr + prev->size != p->addr)
                return false;
        }
    }

    if (prev && prev->addr + prev->size != heap->end)
        return false;

    return true;
}

void Test1()
{
    OE_Heap h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_InitHeap(&h, size) == 0);

    assert(h.initialized == true);
    assert(h.size == size);
    assert(h.base != 0);
    assert((uintptr_t)h.next_vad == h.base);
    assert(h.end_vad == h.next_vad + npages);
    assert(h.start == (uintptr_t)h.end_vad);
    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end);
    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == 0);
    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    void* ptrs[16];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);

        m += r;
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end - m);
    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));

    for (size_t i = 0; i < n; i++)
    {
        if (OE_HeapUnmap(&h, ptrs[i], (i + 1) * PGSZ) != 0)
            assert(0);
    }

    assert(h.mapped_top == h.end);
    assert(_CountVADs(h.free_vads) == n);
    assert(_CountVADs(h.vad_list) == 0);
    assert(_IsSorted(h.vad_list));

    /* Allocate N regions */
    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);
    }

    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (OE_HeapUnmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    assert(_CountVADs(h.free_vads) == n/2);
    assert(_CountVADs(h.vad_list) == n/2);
    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);
    }

    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (OE_HeapUnmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);
    }

    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    printf("=== Passed %s()\n", __FUNCTION__);
}

void Test2()
{
    OE_Heap h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_InitHeap(&h, size) == 0);

    void* p0;
    void* p1;
    void* p2;
    {

        if (!(p0 = OE_HeapMap(&h, NULL, 2*OE_PAGE_SIZE, 0, 0)))
            assert(0);

        if (!(p1 = OE_HeapMap(&h, NULL, 3*OE_PAGE_SIZE, 0, 0)))
            assert(0);

        if (!(p2 = OE_HeapMap(&h, NULL, 4*OE_PAGE_SIZE, 0, 0)))
            assert(0);
    }

    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == 3);
    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    void* p0a;
    void* p0b;
    {
        if (OE_HeapUnmap(&h, p0, 2*OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_CountVADs(h.free_vads) == 1);
        assert(_CountVADs(h.vad_list) == 2);
        assert(_IsSorted(h.vad_list));
        assert(!_IsFlush(&h, h.vad_list));

        if (!(p0a = OE_HeapMap(&h, NULL, OE_PAGE_SIZE, 0, 0)))
            assert(0);
        assert(p0a == p0);

        assert(_CountVADs(h.free_vads) == 0);
        assert(_CountVADs(h.vad_list) == 3);
        assert(_IsSorted(h.vad_list));

        if (!(p0b = OE_HeapMap(&h, NULL, OE_PAGE_SIZE, 0, 0)))
            assert(0);
        assert(p0b == (uint8_t*)p0 + OE_PAGE_SIZE);

        assert(_CountVADs(h.free_vads) == 0);
        assert(_CountVADs(h.vad_list) == 4);
        assert(_IsSorted(h.vad_list));
        assert(_IsFlush(&h, h.vad_list));
    }

    void* p2a;
    void* p2b;
    {
        if (OE_HeapUnmap(&h, p2, 4*OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_CountVADs(h.free_vads) == 1);
        assert(_CountVADs(h.vad_list) == 3);
        assert(_IsSorted(h.vad_list));
        assert(!_IsFlush(&h, h.vad_list));

        if (!(p2a = OE_HeapMap(&h, NULL, OE_PAGE_SIZE, 0, 0)))
            assert(0);
        assert(p2a == p2);

        if (!(p2b = OE_HeapMap(&h, NULL, 3*OE_PAGE_SIZE, 0, 0)))
            assert(0);
        assert(p2b == (uint8_t*)p2 + OE_PAGE_SIZE);

        assert(_IsSorted(h.vad_list));
        assert(_IsFlush(&h, h.vad_list));
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    printf("=== Passed %s()\n", __FUNCTION__);
}

void Test3()
{
    OE_Heap h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_InitHeap(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);

        m += r;
    }

    /* ptrs[0] -- 1 page */
    /* ptrs[1] -- 2 page */
    /* ptrs[2] -- 3 page */
    /* ptrs[3] -- 4 page */
    /* ptrs[4] -- 5 page */
    /* ptrs[5] -- 6 page */
    /* ptrs[6] -- 7 page */
    /* ptrs[7] -- 8 page */

    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end - m);
    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));

    /* This should be illegal since it overruns the end */
    assert(OE_HeapUnmap(&h, ptrs[0], 2*PGSZ) != 0);
    assert(_IsSorted(h.vad_list));
    assert(_IsFlush(&h, h.vad_list));

    /* Unmap ptrs[1] and ptrs[0] */
    if (OE_HeapUnmap(&h, ptrs[1], 3*PGSZ) != 0)
        assert(0);

    assert(_CountVADs(h.free_vads) == 2);
    assert(_CountVADs(h.vad_list) == n-2);
    assert(_IsSorted(h.vad_list));
    assert(!_IsFlush(&h, h.vad_list));

    /* ptrs[0] -- 1 page (free) */
    /* ptrs[1] -- 2 page (free) */
    /* ptrs[2] -- 3 page */
    /* ptrs[3] -- 4 page */
    /* ptrs[4] -- 5 page */
    /* ptrs[5] -- 6 page */
    /* ptrs[6] -- 7 page */
    /* ptrs[7] -- 8 page */

#if 0
    OE_HeapDump(&h, false);
#endif

    /* Free innner 6 pages of ptrs[7] -- [mUUUUUUm] */
    if (OE_HeapUnmap(&h, ptrs[7] + PGSZ, 6*PGSZ) != 0)
        assert(0);

    assert(_CountVADs(h.free_vads) == 1);
    assert(_CountVADs(h.vad_list) == 7);
    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, false);
#endif

    /* Map 6 pages to fill the gap created by last unmap */
    if (!OE_HeapMap(&h, NULL, 6*PGSZ, 0, 0))
        assert(0);

#if 0
    OE_HeapDump(&h, false);
#endif

    printf("=== Passed %s()\n", __FUNCTION__);
}

void Test4()
{
    OE_Heap h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_InitHeap(&h, size) == 0);

    void* ptrs[8];
    size_t n = sizeof(ptrs) / sizeof(ptrs[0]);
    size_t m = 0;

    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = OE_HeapMap(&h, NULL, r, 0, 0)))
            assert(0);

        m += r;
    }

    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end - m);
    assert(_CountVADs(h.free_vads) == 0);
    assert(_CountVADs(h.vad_list) == n);
    assert(_IsSorted(h.vad_list));
#if 0
    OE_HeapDump(&h, false);
#endif

    /* This should fail */
    assert(OE_HeapUnmap(&h, ptrs[7], 1024 * PGSZ) != 0);

    /* Unmap everything */
    assert(OE_HeapUnmap(&h, ptrs[7], m) == 0);
    assert(_CountVADs(h.free_vads) == n);
    assert(_CountVADs(h.vad_list) == 0);

#if 1
    OE_HeapDump(&h, true);
#endif

    printf("=== Passed %s()\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    Test1();
    Test2();
    Test3();
    Test4();
    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
