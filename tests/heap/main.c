#include <openenclave/bits/heap.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>

#define D(X)

static size_t PGSZ = OE_PAGE_SIZE;

static bool _coverage[OE_HEAP_COVERAGE_N];

static void _MergeCoverage(const OE_Heap* heap)
{
    for (size_t i = 0; i < OE_HEAP_COVERAGE_N; i++)
    {
        if (heap->coverage[i])
            _coverage[i] = true;
    }
}

static void _CheckCoverage()
{
    for (size_t i = 0; i < OE_HEAP_COVERAGE_N; i++)
    {
        if (!_coverage[i])
        {
            fprintf(stderr, "*** uncovered: OE_HEAP_COVERAGE_%zu\n", i);
            assert(0);
        }
    }
}

static size_t _CountVADs(const OE_VAD* list)
{
    const OE_VAD* p;
    size_t count = 0;

    for (p = list; p; p = p->next)
        count++;

    return count;
}

static int _InitHeap(OE_Heap* heap, size_t size)
{
    void* base;

    /* Allocate aligned pages */
    if (!(base = memalign(OE_PAGE_SIZE, size)))
        return -1;

    if (OE_HeapInit(heap, (uintptr_t)base, size) != OE_OK)
    {
        fprintf(stderr, "ERROR: OE_HeapInit(): %s\n", heap->err);
        return -1;
    }

    OE_HeapSetSanity(heap, true);

    return 0;
}

static void _FreeHeap(OE_Heap* heap)
{
    free((void*)heap->base);
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

static void* _HeapMap(
    OE_Heap* heap,
    void* addr,
    size_t length)
{
    int prot = OE_PROT_READ | OE_PROT_WRITE;
    int flags = OE_MAP_ANONYMOUS | OE_MAP_PRIVATE;

    void* result = OE_HeapMap(heap, addr, length, prot, flags);

    if (!result)
        fprintf(stderr, "ERROR: OE_HeapMap(): %s\n", heap->err);

    return result;
}

static void* _HeapMapNoErr(
    OE_Heap* heap,
    void* addr,
    size_t length)
{
    int prot = OE_PROT_READ | OE_PROT_WRITE;
    int flags = OE_MAP_ANONYMOUS | OE_MAP_PRIVATE;

    void* result = OE_HeapMap(heap, addr, length, prot, flags);

    return result;
}

static void* _HeapRemap(
    OE_Heap* heap,
    void* addr,
    size_t old_size,
    size_t new_size)
{
    int flags = OE_MREMAP_MAYMOVE;

    void* result = OE_HeapRemap(heap, addr, old_size, new_size, flags);

    if (!result)
        fprintf(stderr, "ERROR: OE_HeapRemap(): %s\n", heap->err);

    return result;
}

static int _HeapUnmap(
    OE_Heap* heap,
    void* address,
    size_t size)
{
    int rc = OE_HeapUnmap(heap, address, size);

    if (rc != 0)
        fprintf(stderr, "ERROR: OE_HeapUnmap(): %s\n", heap->err);

    return rc;
}

void TestHeap1()
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

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);

        m += r;
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end - m);
    assert(_IsSorted(h.vad_list));

    for (size_t i = 0; i < n; i++)
    {
        if (_HeapUnmap(&h, ptrs[i], (i + 1) * PGSZ) != 0)
            assert(0);
    }

    assert(_IsSorted(h.vad_list));

    /* Allocate N regions */
    for (size_t i = 0; i < n; i++)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);
    }

    assert(_IsSorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_HeapUnmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    assert(_IsSorted(h.vad_list));
    assert(_CountVADs(h.vad_list) == n/2);
    assert(_CountVADs(h.free_vads) == 0);

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 0; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);
    }

    assert(_IsSorted(h.vad_list));

    /* Free every other region (leaving N/2 gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (_HeapUnmap(&h, ptrs[i], r) != 0)
            assert(0);
    }

    /* Reallocate every other region (filling in gaps) */
    for (size_t i = 1; i < n; i += 2)
    {
        size_t r = (i + 1) * OE_PAGE_SIZE;

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);
    }

    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestHeap2()
{
    OE_Heap h;

    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    assert(_InitHeap(&h, size) == 0);

    void* p0;
    void* p1;
    void* p2;
    {

        if (!(p0 = _HeapMap(&h, NULL, 2*OE_PAGE_SIZE)))
            assert(0);

        if (!(p1 = _HeapMap(&h, NULL, 3*OE_PAGE_SIZE)))
            assert(0);

        if (!(p2 = _HeapMap(&h, NULL, 4*OE_PAGE_SIZE)))
            assert(0);
    }

    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    void* p0a;
    void* p0b;
    {
        if (_HeapUnmap(&h, p0, 2*OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_IsSorted(h.vad_list));
        assert(!_IsFlush(&h, h.vad_list));

        if (!(p0a = _HeapMap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p0a == p0);

        assert(_IsSorted(h.vad_list));

        if (!(p0b = _HeapMap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p0b == (uint8_t*)p0 + OE_PAGE_SIZE);

        assert(_IsSorted(h.vad_list));
        assert(_IsFlush(&h, h.vad_list));
    }

    void* p2a;
    void* p2b;
    {
        if (_HeapUnmap(&h, p2, 4*OE_PAGE_SIZE) != 0)
            assert(0);

        assert(_IsSorted(h.vad_list));
        assert(_IsFlush(&h, h.vad_list));

        if (!(p2a = _HeapMap(&h, NULL, OE_PAGE_SIZE)))
            assert(0);
        assert(p2a == (uint8_t*)p2 + 3*OE_PAGE_SIZE);

        if (!(p2b = _HeapMap(&h, NULL, 3*OE_PAGE_SIZE)))
            assert(0);
        assert(p2b == p2);

        assert(_IsSorted(h.vad_list));
        assert(_IsFlush(&h, h.vad_list));
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestHeap3()
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

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
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
    assert(_IsSorted(h.vad_list));

    /* This should be illegal since it overruns the end */
    assert(OE_HeapUnmap(&h, ptrs[0], 2*PGSZ) != 0);
    assert(_IsSorted(h.vad_list));
    assert(_IsFlush(&h, h.vad_list));

    /* Unmap ptrs[1] and ptrs[0] */
    if (_HeapUnmap(&h, ptrs[1], 3*PGSZ) != 0)
        assert(0);

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
    if (_HeapUnmap(&h, ptrs[7] + PGSZ, 6*PGSZ) != 0)
        assert(0);

    assert(_IsSorted(h.vad_list));

#if 0
    OE_HeapDump(&h, false);
#endif

    /* Map 6 pages to fill the gap created by last unmap */
    if (!_HeapMap(&h, NULL, 6*PGSZ))
        assert(0);

#if 0
    OE_HeapDump(&h, false);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestHeap4()
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

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);

        m += r;
    }

    assert(h.break_top == h.start);
    assert(h.mapped_top == h.end - m);
    assert(_IsSorted(h.vad_list));
#if 0
    OE_HeapDump(&h, false);
#endif

    /* This should fail */
    assert(OE_HeapUnmap(&h, ptrs[7], 1024 * PGSZ) != 0);

    /* Unmap everything */
    assert(_HeapUnmap(&h, ptrs[7], m) == 0);

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestHeap5()
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

        if (!(ptrs[i] = _HeapMap(&h, NULL, r)))
            assert(0);

        m += r;
    }

#if 0
    OE_HeapDump(&h, true);
#endif

    /* Unmap a region in the middle */
    assert(_HeapUnmap(&h, ptrs[4], 5 * PGSZ) == 0);

    /* Unmap everything */
    assert(OE_HeapUnmap(&h, ptrs[7], m) != 0);

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestHeap6()
{
    OE_Heap h;
    size_t i;
    const size_t n = 8;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_InitHeap(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    if (!(ptr = _HeapMap(&h, NULL, n * PGSZ)))
        assert(0);

    /* Unmap 8 pages, 1 page at a time */
    for (i = 0; i < n; i++)
    {
        void* p = ptr + (i * PGSZ);
        assert(_HeapUnmap(&h, p, PGSZ) == 0);
    }


#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRemap1()
{
    OE_Heap h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_InitHeap(&h, size) == 0);

    void* ptr;

    /* Map N pages */
    old_size = 8*PGSZ;
    if (!(ptr = _HeapMap(&h, NULL, old_size)))
        assert(0);

#if 0
    OE_HeapDump(&h, true);
#endif

    assert(_IsSorted(h.vad_list));
    assert(_IsFlush(&h, h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    /* Remap region, making it twice as big */
    new_size = 16*PGSZ;
    if (!(ptr = _HeapRemap(&h, ptr, old_size, new_size)))
        assert(0);

    assert(_IsSorted(h.vad_list));
    assert(!_IsFlush(&h, h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    /* Remap region, making it four times smaller */
    old_size = new_size;
    new_size = 4*PGSZ;
    if (!(ptr = _HeapRemap(&h, ptr, old_size, new_size)))
        assert(0);

    assert(_IsSorted(h.vad_list));
    assert(!_IsFlush(&h, h.vad_list));

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRemap2()
{
    OE_Heap h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;
    size_t old_size;
    size_t new_size;

    assert(_InitHeap(&h, size) == 0);


    /* Map N pages */
    old_size = 8*PGSZ;
    void* ptr1;
    if (!(ptr1 = _HeapMap(&h, NULL, old_size)))
        assert(0);

    /* Map N pages */
    old_size = 8*PGSZ;
    void* ptr2;
    if (!(ptr2 = _HeapMap(&h, NULL, old_size)))
        assert(0);

#if 0
    OE_HeapDump(&h, true);
#endif

    /* Remap region, making it twice as big */
    new_size = 16*PGSZ;
    if (!(ptr2 = _HeapRemap(&h, ptr2, old_size, new_size)))
        assert(0);

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRemap3()
{
    OE_Heap h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_InitHeap(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    OE_Page* ptr1;
    if (!(ptr1 = (OE_Page*)_HeapMap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    OE_Page* ptr2;
    if (!(ptr2 = (OE_Page*)_HeapMap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Set pointer to overlapped region: [3|4] */
    OE_Page* ptr3 = ptr2 + 3;

#if 0
    OE_HeapDump(&h, false);
#endif

    /* Shrink region: [3|4] */
    if (!(ptr3 = (OE_Page*)_HeapRemap(&h, ptr3, 2*PGSZ, 1*PGSZ)))
        assert(0);

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestRemap4()
{
    OE_Heap h;
    const size_t npages = 1024;
    const size_t size = npages * OE_PAGE_SIZE;

    assert(_InitHeap(&h, size) == 0);

    /* Map 4 pages: [4|5|6|7] */
    OE_Page* ptr1;
    if (!(ptr1 = (OE_Page*)_HeapMap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Map 4 pages: [0|1|2|3] */
    OE_Page* ptr2;
    if (!(ptr2 = (OE_Page*)_HeapMap(&h, NULL, 4 * PGSZ)))
        assert(0);

    /* Result: [0|1|2|3|4|5|6|7] */
    assert(ptr2 + 4 == ptr1);

    /* Unmap [4|5|6|7] */
    assert(_HeapUnmap(&h, ptr1, 4 * PGSZ) == 0);

#if 0
    OE_HeapDump(&h, false);
#endif

    OE_Page* ptr3 = ptr2 + 2;

    /* Expand region: [2|3] */
    if (!(ptr3 = (OE_Page*)_HeapRemap(&h, ptr3, 2 * PGSZ, 4 * PGSZ)))
        assert(0);

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

typedef struct _Elem
{
    void* addr;
    size_t size;
}
Elem;

static void _SetMem(Elem* elem)
{
    uint8_t* p = (uint8_t*)elem->addr;
    const size_t n = elem->size;

    for (size_t i = 0; i < n; i++)
    {
        p[i] = n % 251;
    }
}

static bool _CheckMem(Elem* elem)
{
    const uint8_t* p = (const uint8_t*)elem->addr;
    const size_t n = elem->size;

    for (size_t i = 0; i < n; i++)
    {
        if (p[i] != (uint8_t)(n % 251))
            return false;
    }

    return true;
}

void TestHeapRandomly()
{
    OE_Heap h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_InitHeap(&h, heap_size) == 0);

    static Elem elem[1024];
    const size_t N = sizeof(elem) / sizeof(elem[0]);
    const size_t M = 20000;

    for (size_t i = 0; i < M; i++)
    {
        size_t r = rand() % N;

        if (elem[r].addr)
        {
            assert(_CheckMem(&elem[r]));

            if (rand() % 2)
            {
                D(printf("unmap: addr=%p size=%zu\n", 
                    elem[r].addr, elem[r].size);)

                assert(_HeapUnmap(&h, elem[r].addr, elem[r].size) == 0);
                elem[r].addr = NULL;
                elem[r].size = 0;
            }
            else
            {
                void* addr = elem[r].addr;
                assert(addr);

                size_t old_size = elem[r].size;
                assert(old_size > 0);

                size_t new_size = (rand() % 16 + 1) * PGSZ;
                assert(new_size > 0);

                D(printf("remap: addr=%p old_size=%zu new_size=%zu\n", 
                    addr, old_size, new_size);)

                addr = _HeapRemap(&h, addr, old_size, new_size);
                assert(addr);

                elem[r].addr = addr;
                elem[r].size = new_size;
                _SetMem(&elem[r]);
            }
        }
        else
        {
            size_t size = (rand() % 16 + 1) * PGSZ;
            assert(size > 0);

            void* addr = _HeapMap(&h, NULL, size);
            assert(addr);

            D(printf("map: addr=%p size=%zu\n", addr, size);)

            elem[r].addr = addr;
            elem[r].size = size;
            _SetMem(&elem[r]);
        }
    }

    /* Unmap all remaining memory */
    for (size_t i = 0; i < N; i++)
    {
        if (elem[i].addr)
        {
            D(printf("addr=%p size=%zu\n", elem[i].addr, elem[i].size);)
            assert(_CheckMem(&elem[i]));
            assert(_HeapUnmap(&h, elem[i].addr, elem[i].size) == 0);
        }
    }

    /* Everything should be unmapped */
    assert(h.vad_list == NULL);

    assert(OE_HeapSane(&h));

#if 0
    OE_HeapDump(&h, true);
#endif

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

void TestOutOfMemory()
{
    OE_Heap h;
    const size_t heap_size = 64 * 1024 * 1024;

    assert(_InitHeap(&h, heap_size) == 0);

    /* Use up all the memory */
    while (_HeapMapNoErr(&h, NULL, 64*PGSZ))
        ;

    assert(OE_HeapSane(&h));

    _MergeCoverage(&h);
    _FreeHeap(&h);
    printf("=== passed %s()\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    TestHeap1();
    TestHeap2();
    TestHeap3();
    TestHeap4();
    TestHeap5();
    TestHeap6();
    TestRemap1();
    TestRemap2();
    TestRemap3();
    TestRemap4();
    TestHeapRandomly();
    TestOutOfMemory();
    _CheckCoverage();
    printf("=== passed all tests (%s)\n", argv[0]);
    return 0;
}
