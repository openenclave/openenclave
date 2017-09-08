#ifdef OE_BUILD_ENCLAVE
# include <openenclave/enclave.h>
#else
# include <openenclave/host.h>
#endif

#include <openenclave/bits/galloc.h>

#ifdef OE_BUILD_ENCLAVE
# include <openenclave/enclave.h>
#else
# include <openenclave/host.h>
# include <string.h>
# include <stdlib.h>
# include <stdio.h>
# include <wchar.h>
# include <ctype.h>
# include <stdarg.h>
#endif

#ifdef OE_BUILD_ENCLAVE
# define MEMCPY OE_Memcpy
# define MALLOC OE_Malloc
# define FREE OE_Free
#else
# define MEMCPY memcpy
# define MALLOC malloc
# define FREE free
#endif

/*
**==============================================================================
**
** galloc.c
**
**     This file implements a guarded allocation scheme, whereby each memory
**     allocation is placeed between two guard variables. The goal is to
**     detect buffer overflows and underflows by checking whether either 
**     guard has been disrupted. The layout of a memory object is:
**
**         [MAGIC] [USER-DATA-SIZE] [GUARD] [USER-DATA] [GUARD]
**
**     __OE_GMalloc() creates an object with this layout and returns a pointer 
**     to user porition.
**
**     __OE_GCheck() checks whether either of the guards has been disrupted.
**
**     __OE_GFree() releases a memory object after performing a check. 
**     Releases memory to default allocator if not owner of memory.
**
**==============================================================================
*/

/* ATTN: write function to OE_Free the hash list */

static const unsigned int _MAGIC = 0x444E5BCE;

typedef struct _Block Block;

struct _Block
{
    Block* next;
    size_t size;
    unsigned int magic;
    unsigned int guard;
};

static unsigned int _ComputeGuard(const void* ptr)
{
    static const unsigned int XORAND = 0XBB5D2CA3;

    if (sizeof(void*) == 4)
    {
        uint32_t addr = (uint32_t)(uint64_t)ptr;
        return addr ^ XORAND;
    }

    if (sizeof(void*) == 8)
    {
        uint64_t addr = (uint64_t)ptr;
        uint32_t hi = (uint32_t)(addr >> 32);
        uint32_t lo = (uint32_t)(addr & 0x00000000FFFFFFFF);
        return hi ^ lo ^ XORAND;
    }

    /* 16-byte pointers not handled yet */
    return XORAND;
}

OE_INLINE void* _BlockToPtr(Block* block)
{
    if (!block)
        return NULL;

    return block + 1;
}

OE_INLINE Block* _PtrToBlock(void* ptr)
{
    if (!ptr)
        return NULL;

    return (Block*)ptr - 1;
}

/* A hash table of unfreed allocations */
static Block* _chains[1023];
static size_t _nchains = OE_COUNTOF(_chains);

static size_t _Hash(const void* ptr)
{
    /* Discard lower three bits (always zero) */
    return (((uint64_t)ptr) >> 3) % _nchains;
}

static void _HashInsert(Block* block)
{
    uint64_t index = _Hash(_BlockToPtr(block));

    /* Insert as first element of the chain */
    block->next = _chains[index];
    _chains[index] = block;
}

static int _HashRemove(void* ptr)
{
    uint64_t index = _Hash(ptr);
    Block* p;
    Block* prev = NULL;

    for (p = _chains[index]; p; p = p->next)
    {
        if (_BlockToPtr(p) == ptr)
        {
            if (prev)
            {
                /* Remove embedded list member */
                prev->next = p->next;
            }
            else
            {
                /* Remove first list element */
                _chains[index] = p->next;
            }

            return 0;
        }

        prev = p;
    }

    /* Not found! */
    return -1;
}

static size_t _HashSize(void)
{
    size_t size = 0;
    size_t i;

    for (i = 0; i < _nchains; i++)
    {
        Block* p;

        for (p = _chains[i]; p; p = p->next)
            size++;
    }

    return size;
}

static bool _HashContains(const void* ptr)
{
    uint64_t index = _Hash(ptr);
    Block* p;

    for (p = _chains[index]; p; p = p->next)
    {
        if (_BlockToPtr(p) == ptr)
            return true;
    }

    /* Not found! */
    return false;
}

void* __OE_GMalloc(
    size_t size)
{
    Block* block;
    size_t n;
    unsigned int guard;

    /* Calculate size of block: [MAGIC] [GUARD] [DATA] [GUARD] */
    n = sizeof(Block) + size + sizeof(unsigned int);

    if (!(block = (Block*)MALLOC(n)))
        return NULL;

    /* Compute guard */
    guard = _ComputeGuard(_BlockToPtr(block));

    /* Initalize the block header */
    block->magic = _MAGIC;
    block->size = size;
    block->guard = guard;

    /* The second guard is not necessarily aligned on a 4-byte boundary */
    MEMCPY((uint8_t*)_BlockToPtr(block) + size, &guard, sizeof(uint32_t));

    /* Insert into hash table */
    _HashInsert(block);

    return _BlockToPtr(block);
}

static int _GCheck(
    void* ptr)
{
    Block* block;
    unsigned int guard;

    if (!ptr)
        return 0;

    block = _PtrToBlock(ptr);

    if (block->magic != _MAGIC)
        return -1;

    if (block->guard != _ComputeGuard(ptr))
        return -1;

    /* The second guard is not necessarily aligned on a 4-byte boundary */
    MEMCPY(&guard, (uint8_t*)ptr + block->size, sizeof(uint32_t));
    if (guard != _ComputeGuard(ptr))
        return -1;

    /* The second guard is not necessarily aligned on a 4-byte boundary */
    return 0;
}

int __OE_GCheck(
    void* ptr)
{
    if (!_HashContains(ptr))
        return 0;

    return _GCheck(ptr);
}

void __OE_GFree(
    void* ptr)
{
    if (!ptr)
        return;

    /* If ptr wasn't allocated by __OE_GMalloc(), then pass to OE_Free() */
    if (_HashRemove(ptr) != 0)
    {
        FREE(ptr);
        return;
    }

#ifndef OE_BUILD_ENCLAVE
    if (_GCheck(ptr) != 0)
    {
        printf("WARNING: __OE_GFree(): corrupt block!\n");
    }
#endif

    FREE(_PtrToBlock(ptr));
}

size_t __OE_GCount()
{
    return _HashSize();
}

bool __OE_GOwns(const void* ptr)
{
    return _HashContains(ptr);
}

void __OE_GFix(
    void* ptr)
{
    Block* block;

    if (!ptr)
        return;

    if (!_HashContains(ptr))
        return;

    block = _PtrToBlock(ptr);
    block->guard = _ComputeGuard(ptr);
    MEMCPY((uint8_t*)ptr + block->size, &block->guard, sizeof(uint32_t));
}
