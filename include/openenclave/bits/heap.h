#ifndef _OE_HEAP_H
#define _OE_HEAP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>
#include <openenclave/bits/search.h>
#include <openenclave/thread.h>

#define OE_PROT_NONE       0
#define OE_PROT_READ       1
#define OE_PROT_WRITE      2
#define OE_PROT_EXEC       4

#define OE_MAP_SHARED      1
#define OE_MAP_PRIVATE     2
#define OE_MAP_FIXED       16
#define OE_MAP_ANONYMOUS   32

#define OE_MAP_FAILED      ((void*)-1)

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

/* OE_Heap data structures and fields */
typedef struct _OE_Heap
{
    /* True if OE_HeapInit() has been called */
    bool initialized;

    /* Spin lock to synchronize access to this object */
    OE_Spinlock lock;

    /* Base of heap */
    uintptr_t base;

    /* Size of heap */
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
}
OE_Heap;

int OE_HeapInit(
    OE_Heap* heap,
    uintptr_t base,
    size_t size);

void* OE_HeapMap(
    OE_Heap* heap,
    void* address,
    size_t size,
    int prot,
    int flags);

int OE_HeapUnmap(
    OE_Heap* heap,
    void* address,
    size_t size);

void OE_HeapDump(
    const OE_Heap* heap);

#endif /* _OE_HEAP_H */
