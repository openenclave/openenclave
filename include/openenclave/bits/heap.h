#ifndef _OE_HEAP_H
#define _OE_HEAP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include <openenclave/bits/search.h>
#include <openenclave/thread.h>
#include <openenclave/result.h>

#define OE_PROT_NONE       0
#define OE_PROT_READ       1
#define OE_PROT_WRITE      2
#define OE_PROT_EXEC       4

#define OE_MAP_SHARED      1
#define OE_MAP_PRIVATE     2
#define OE_MAP_FIXED       16
#define OE_MAP_ANONYMOUS   32

#define OE_MREMAP_MAYMOVE  1

#define OE_HEAP_ERROR_SIZE 256

/* Virtual Address Descriptor */
typedef struct _OE_VAD
{
    /* Tree node for AVL tree */
    struct OE_Tnode tnode;

    /* Pointer to next OE_VAD on linked list */
    struct _OE_VAD* next;

    /* Pointer to previous OE_VAD on linked list */
    struct _OE_VAD* prev;

    /* Address of this memory region */
    uintptr_t addr;

    /* Size of this memory region in bytes */
    uint32_t size;

    /* Protection flags for this region OE_PROT_???? */
    uint16_t prot;

    /* Mapping flags for this region: OE_MAP_???? */
    uint16_t flags;
}
OE_VAD;

OE_STATIC_ASSERT(sizeof(OE_VAD) == 64);

#define OE_HEAP_MAGIC 0xcc8e1732ebd80b0b

#define OE_HEAP_INITIALIZER { 0, false, OE_SPINLOCK_INITIALIZER }

#define OE_HEAP_ERR_SIZE 256

/* Heap Code coverage */
typedef enum _OE_HeapCoverage
{
    OE_HEAP_COVERAGE_0,
    OE_HEAP_COVERAGE_1,
    OE_HEAP_COVERAGE_2,
    OE_HEAP_COVERAGE_3,
    OE_HEAP_COVERAGE_4,
    OE_HEAP_COVERAGE_5,
    OE_HEAP_COVERAGE_6,
    OE_HEAP_COVERAGE_7,
    OE_HEAP_COVERAGE_8,
    OE_HEAP_COVERAGE_9,
    OE_HEAP_COVERAGE_10,
    OE_HEAP_COVERAGE_11,
    OE_HEAP_COVERAGE_12,
    OE_HEAP_COVERAGE_13,
    OE_HEAP_COVERAGE_14,
    OE_HEAP_COVERAGE_15,
    OE_HEAP_COVERAGE_16,
    OE_HEAP_COVERAGE_17,
    OE_HEAP_COVERAGE_18,
    OE_HEAP_COVERAGE_N,
}
OE_HeapCoverage;

/* OE_Heap data structures and fields */
typedef struct _OE_Heap
{
    /* Magic number (OE_HEAP_MAGIC) */
    uint64_t magic;

    /* True if OE_HeapInit() has been called */
    bool initialized;

    /* Base of heap (aligned on page boundary) */
    uintptr_t base;

    /* Size of heap (a multiple of OE_PAGE_SIZE) */
    size_t size;

    /* Start of heap (immediately aft4er VADs array) */
    uintptr_t start;

    /* End of heap (points to first page after end of heap) */
    uintptr_t end;

    /* Top of break memory partition (grows positively) */
    uintptr_t break_top;

    /* Top of mapped memory partition (grows negatively) */
    uintptr_t mapped_top;

    /* The next available OE_VAD in the VADs array */
    OE_VAD* next_vad;

    /* The end of the VADs array */
    OE_VAD* end_vad;

    /* The OE_VAD free list (singly linked) */
    OE_VAD* free_vads;

    /* Root of OE_VAD AVL tree */
    OE_VAD* vad_tree;

    /* Linked list of VADs (sorted by address and doubly linked) */
    OE_VAD* vad_list;

    /* Whether sanity checks are enabled: see OE_HeapEnableSanityChecks() */
    bool sanity;

    /* Whether to scrub memory when it is unmapped (fill with 0xDD) */
    bool scrub;

    /* Error string */
    char err[OE_HEAP_ERROR_SIZE];

    /* Code coverage array */
    bool coverage[OE_HEAP_COVERAGE_N];
}
OE_Heap;

OE_Result OE_HeapInit(
    OE_Heap* heap,
    uintptr_t base,
    size_t size);

void* OE_HeapMap(
    OE_Heap* heap,
    void* addr,
    size_t length,
    int prot,
    int flags);

void* OE_HeapRemap(
    OE_Heap* heap,
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags);

OE_Result OE_HeapUnmap(
    OE_Heap* heap,
    void* address,
    size_t size);

void OE_HeapDump(
    const OE_Heap* h, 
    bool full);

void* OE_HeapSbrk(
    OE_Heap* heap,
    ptrdiff_t increment);

OE_Result OE_HeapBrk(
    OE_Heap* heap,
    uintptr_t addr);

void OE_HeapSetSanity(
    OE_Heap* heap,
    bool sanity);

bool OE_HeapSane(
    OE_Heap* heap);

void* OE_Map(
    void* addr,
    size_t length,
    int prot,
    int flags);

void* OE_Remap(
    void* addr,
    size_t old_size,
    size_t new_size,
    int flags);

OE_Result OE_Unmap(
    void* address,
    size_t size);

#endif /* _OE_HEAP_H */
