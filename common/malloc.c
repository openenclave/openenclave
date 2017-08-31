#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <openenclave.h>
#include <oeinternal/malloc.h>

#ifdef OE_BUILD_ENCLAVE
# include <oeinternal/globals.h>
#endif

#if 0
# define ASSERT(COND) assert(COND)
# define WARN fprintf(stderr, "WARN: %s(%u)\n", __FILE__, __LINE__)
#else
# define ASSERT(COND)
# define WARN
#endif

/*
**==============================================================================
**
** Check for function name defintions
**
**==============================================================================
*/

#ifndef OE_MALLOC
# error "please defined OE_MALLOC"
#endif

#ifndef OE_MEMALIGN
# error "please defined OE_MEMALIGN"
#endif

#ifndef OE_CALLOC
# error "please defined OE_CALLOC"
#endif

#ifndef OE_REALLOC
# error "please defined OE_REALLOC"
#endif

#ifndef OE_FREE
# error "please defined OE_FREE"
#endif

/*
**==============================================================================
**
** _IsPow2()
**
**     Return true if x is a power of two or zero
**
**==============================================================================
*/

OE_INLINE bool _IsPow2(size_t x)
{
    return ((x & (x - 1)) == 0) ? true : false;
}

/*
**==============================================================================
**
** _Round()
**
**     Round x to next multiple of m
**
**==============================================================================
*/

OE_INLINE uint64_t _Round(uint64_t x, uint64_t m)
{
    return ((x + m - 1) / m) * m;
}

/*
**==============================================================================
**
** Lock for synchronizing access to shared data structures
**
**==============================================================================
*/

static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;

/*
**==============================================================================
**
** Header:
**
**==============================================================================
*/

#define HEADER_FREE 0xAB
#define HEADER_BUSY 0x12

typedef struct _Header
{
    /* Indicates whether block is busy (HEADER_BUSY) or free (HEADER_FREE) */
    uint64_t magic:8;

    /* Offset to secondary alignment header or zero if none */
    uint64_t offset:24;

    /* Size of the user area including aligment bytes */
    uint64_t size:32;
}
Header;

OE_CHECK_SIZE(sizeof(Header),8);

OE_INLINE void _InitHeader(
    Header* header, 
    bool busy,
    uint32_t offset, 
    uint64_t size)
{
    header->magic = busy ? HEADER_BUSY : HEADER_FREE;
    header->offset = offset;
    header->size = size;
}

/*
**==============================================================================
**
** Trailer:
**
**==============================================================================
*/

#define TRAILER_FREE 0xCD
#define TRAILER_BUSY 0x34

typedef struct _Trailer
{
    /* Indicates whether block is busy (TRAILER_BUSY) or free (TRAILER_FREE) */
    uint64_t magic:8;

    /* Offset to secondary alignment header or zero if none */
    uint64_t offset:24;

    /* Size of the user area including aligment bytes */
    uint64_t size:32;
}
Trailer;

OE_CHECK_SIZE(sizeof(Trailer),8);

OE_INLINE void _InitTrailer(
    Trailer* trailer, 
    bool busy,
    uint32_t offset, 
    uint64_t size)
{
    trailer->magic = busy ? TRAILER_BUSY : TRAILER_FREE;
    trailer->offset = offset;
    trailer->size = size;
}

static Trailer* _GetTrailer(void* block)
{
    Header* header = (Header*)block;
    return (Trailer*)((uint8_t*)block + sizeof(Header) + header->size);
}

/*
**==============================================================================
**
** _InitBlock()
**
**     Initialize a block by initializing the header, trailer, and optionally
**     the alignment header.
**
**==============================================================================
*/

static void* _InitBlock(
    void* block_,
    bool busy,
    uint32_t alignment, 
    uint64_t size)
{
    uint8_t* block = (uint8_t*)block_;
    Header* header = (Header*)block;
    uint8_t* ptr = block + sizeof(Header);
    Trailer* trailer = (Trailer*)(ptr + size);
    uint64_t offset = 0;

    /* Calculate data offset and initialize aligment header (if necessary) */
    if (alignment > sizeof(uint64_t))
    {
        uint64_t addr = (uint64_t)ptr;
        offset = _Round(addr, alignment) - addr;

        ASSERT(offset < size);
        ASSERT(size - offset > sizeof(uint64_t));

        /* Move pointer up to aligment boundary */
        ptr += offset;

        _InitHeader((Header*)(ptr - sizeof(Header)), busy, offset, size);
    }

    /* Initialize header */
    _InitHeader(header, busy, offset, size);

    /* Initialize trailer */
    _InitTrailer(trailer, busy, offset, size);

    return ptr;
}

/*
**==============================================================================
**
** OE_InitMalloc()
**
**     User of this library must call this function to initialize the library.
**
**==============================================================================
*/

static uint8_t* _base;
static uint8_t* _end;
static uint8_t* _ptr;

static int _initialized = 0;

int OE_InitMalloc(void* base, size_t size)
{
    if (_initialized)
        return 0;

    /* Fail if base not on a word boundary */
    if ((uint64_t)base % sizeof(uint64_t))
        return -1;

    /* Fail if size is less than one word */
    if (size < sizeof(uint64_t))
        return -1;

    _base = (uint8_t*)base;
    _end = _base + size;
    _ptr = _base;

    _initialized = 1;

    return 0;
}

#ifdef OE_BUILD_ENCLAVE
static void _InitializeAux(void)
{
    if (_initialized == 0)
    {
        OE_SpinLock(&_lock);

        if (_initialized == 0)
        {
            OE_InitMalloc((void*)__OE_GetHeapBase(), __OE_GetHeapSize());
            _initialized = 1;
        }

        OE_SpinUnlock(&_lock);
    }
}
#endif /* OE_BUILD_ENCLAVE */

OE_INLINE void _Initialize(void)
{
#ifdef OE_BUILD_ENCLAVE

    if (_initialized == 0)
        _InitializeAux();

#endif /* OE_BUILD_ENCLAVE */
}

/*
**==============================================================================
**
** _PtrToBlock()
**
**     Find the start of the block for this pointer.
**
**==============================================================================
*/

static Header* _PtrToBlock(void* ptr_)
{
    uint8_t* ptr = (uint8_t*)ptr_;
    
    if (!ptr)
        return NULL;

    Header* header = (Header*)(ptr - sizeof(Header));

    if (header->magic != HEADER_BUSY)
        return NULL;

    if (header->offset)
    {
        header = (Header*)(ptr - header->offset - sizeof(Header));

        if (header->magic != HEADER_BUSY)
            return NULL;
    }

    return header;
}

/*
**==============================================================================
**
** _BlockToPtr()
**
**     Find the start of user memory given a block
**
**==============================================================================
*/

static __inline__ void* _BlockToPtr(void* block_)
{
    uint8_t* block = (uint8_t*)block_;
    
    if (!block)
        return NULL;

    Header* header = (Header*)block;

    return block + sizeof(Header) + header->offset;
}

/*
**==============================================================================
**
** The Free List
**
**==============================================================================
*/

#define NULL_OFFSET ((uint32_t)0xFFFFFFFF)

typedef struct _FreeBlock
{
    Header header;

    /* Offset (within heap) of previous free block */
    uint32_t prev;

    /* Offset (within heap) of next free block */
    uint32_t next;
}
FreeBlock;

OE_INLINE void _SetLink(uint32_t* off, const FreeBlock* ptr)
{
    if (ptr)
        *off = (uint8_t*)ptr - _base;
    else
        *off = NULL_OFFSET;
}

OE_INLINE FreeBlock* _GetLink(uint32_t off)
{
    if (off == NULL_OFFSET)
        return NULL;

    return (FreeBlock*)(_base + off);
}

OE_CHECK_SIZE(sizeof(FreeBlock),16);

#define NUM_LISTS 128

/* Free lists for sizes that are multiples of word size */
static FreeBlock* _lists[NUM_LISTS];

OE_INLINE size_t _GetListIndex(size_t size)
{
    size_t index = size / sizeof(uint32_t);

    if (index >= NUM_LISTS)
        index = NUM_LISTS - 1;

    return index;
}

OE_INLINE FreeBlock** _GetListRef(size_t size)
{
    return &_lists[_GetListIndex(size)];
}

static void _ListRemove(FreeBlock** list, Header* block)
{
    FreeBlock* fb = (FreeBlock*)block;
    FreeBlock* next = _GetLink(fb->next);
    FreeBlock* prev = _GetLink(fb->prev);

    /* If first on list */
    if (fb == (*list))
    {
        if (next)
            next->prev = NULL_OFFSET;

        (*list) = next;
    }
    else
    {
        if (prev)
            prev->next = fb->next;

        if (next)
            next->prev = fb->prev;
    }

    fb->prev = NULL_OFFSET;
    fb->next = NULL_OFFSET;
}

static void _ListInsert(FreeBlock** list, Header* block_)
{
    FreeBlock* fb = (FreeBlock*)block_;

    if ((*list))
    {
        fb->prev = NULL_OFFSET;
        _SetLink(&(*list)->prev, fb);
        _SetLink(&fb->next, (*list));
        (*list) = fb;
    }
    else
    {
        (*list) = fb;
        fb->prev = NULL_OFFSET;
        fb->next = NULL_OFFSET;
    }
}

/* Find a block big enough for the given request */
static Header* _ListFindAndRemove(FreeBlock** list, size_t size)
{
    FreeBlock* p;

    for (p = (*list); p; p = _GetLink(p->next))
    {
        if (p->header.size >= size)
        {
            _ListRemove(list, (Header*)p);
            return (Header*)p;
        }
    }

    return NULL;
}

static size_t _ListSize(FreeBlock* list)
{
    FreeBlock* p;
    size_t n = 0;

    for (p = list; p; p = _GetLink(p->next))
        n++;

    return n;
}

static Header* _FreeListGet(size_t size)
{
    /* Search for match in the exact size lists */
    for (size_t i = _GetListIndex(size); i < NUM_LISTS - 1; i++)
    {
        FreeBlock* fb = _lists[i];

        if (fb)
        {
            ASSERT(fb->size >= size);
            _ListRemove(&_lists[i], (Header*)fb);
            return (Header*)fb;
        }
    }

    /* Search the final free list with mixed size list */
    return _ListFindAndRemove(&_lists[NUM_LISTS - 1], size);
}

static void _FreeListPut(Header* block)
{
    _ListInsert(_GetListRef(block->size), block);
}

static size_t _FreeListSize(void)
{
    size_t n = 0;

    for (size_t i = 0; i < NUM_LISTS; i++)
        n += _ListSize(_lists[i]);

    return n;
}

/*
**==============================================================================
**
** _IsFirstBlock()
**
**     Return true if this block is the first one on the heap.
**
**==============================================================================
*/

static bool _IsFirstBlock(const void* block)
{
    return block == (_base + sizeof(uint64_t)) ? true : false;
}

/*
**==============================================================================
**
** _IsLastBlock()
**
**     Return true if this block is the last one on the heap.
**
**==============================================================================
*/

static bool _IsLastBlock(const void* block_)
{
    const Header* header = (const Header*)block_;

    const uint8_t* p = (const uint8_t*)block_;
    p += sizeof(Header);
    p += header->size;
    p += sizeof(Trailer);

    return p == _ptr ? true : false;
}

/*
**==============================================================================
**
** _GetLeftNeighbor()
**
**     Get the right neighbor of the given block.
**
**==============================================================================
*/

static Header* _GetLeftNeighbor(const void* block_)
{
    uint8_t* block = (uint8_t*)block_;
    
    if (!block || _IsFirstBlock(block))
        return NULL;

    /* Get trailer of right block */
    Trailer* trailer = (Trailer*)(block - sizeof(Trailer));

    if (trailer->magic != TRAILER_FREE)
        return NULL;

    /* Find header of right block */
    Header* right = (Header*)(
        (uint8_t*)trailer - trailer->size - sizeof(Header));

    _ListRemove(_GetListRef(right->size), right);

    return right;
}

/*
**==============================================================================
**
** _GetRightNeighbor()
**
**     Get the right neigbor of the given block if free.
**
**==============================================================================
*/

static Header* _GetRightNeighbor(const void* block_)
{
    uint8_t* block = (uint8_t*)block_;
    
    if (!block || _IsLastBlock(block))
        return NULL;

    /* Get header of this block */
    Header* h = (Header*)block;

    Header* right = (Header*)(
        block + sizeof(Header) + h->size + sizeof(Trailer));

    if (right->magic != HEADER_FREE)
        return NULL;

    _ListRemove(_GetListRef(right->size), right);

    return right;
}

/*
**==============================================================================
**
** _Reserve()
**
**     Reserve size bytes from the heap. Size must be a multiple of the word
**     size. The lock has been acquired.
**
**==============================================================================
*/

/* The minimum block size: [HEADER | USERMEMORY | TRAILER] */
#define MIN_BLOCK_SIZE (sizeof(Header) + sizeof(uint64_t) + sizeof(Trailer))

static void* _Reserve(size_t size)
{
    void* ptr;

    /* Fail if OE_InitMalloc() was never called */
    if (!_initialized)
        return NULL;

    /* Fail if size is less than minimum block size */
    if (size < MIN_BLOCK_SIZE)
        return NULL;

    /* Fail if size is not a multiple of the word size */
    if (size % sizeof(uint64_t))
        return NULL;

    /* Fail if not enough room on heap */
    if (_end - _ptr < size)
        return NULL;

    /* Reserve the block */
    ptr = _ptr;
    _ptr += size;

    return ptr;
}

/*
**==============================================================================
**
** _CheckBusyBlock()
**
**     Return true if the given pointer refers to a valid block obtained
**     with this allocator.
**
**==============================================================================
*/

static bool _CheckBusyBlock(const void* ptr_)
{
    const uint8_t* ptr = (const uint8_t*)ptr_;

    if (!ptr)
    {
        WARN;
        return false;
    }

    /* Check the header (the inner header if an aligned block) */
    const Header* header;
    {
        header = (const Header*)(ptr - sizeof(Header));

        if (header->magic != HEADER_BUSY)
        {
            WARN;
            return false;
        }

        if (header->size == 0)
        {
            WARN;
            return false;
        }
    }

    /* If this is an aligned block, then check the leading header */
    if (header->offset)
    {
        header = (const Header*)(ptr - header->offset - sizeof(Header));

        if (header->magic != HEADER_BUSY)
        {
            WARN;
            return false;
        }

        if (header->size == 0)
        {
            WARN;
            return false;
        }
    }

    /* Check the trailer */
    const Trailer* trailer;
    {
        trailer = (const Trailer*)(
            (uint8_t*)header + sizeof(Header) + header->size);

        if (trailer->magic != TRAILER_BUSY)
        {
            WARN;
            return false;
        }

        if (trailer->size != header->size)
        {
            WARN;
            return false;
        }

        if (trailer->offset != header->offset)
        {
            WARN;
            return false;
        }
    }

    return true;
}

/*
**==============================================================================
**
** _CheckAlignment()
**
**==============================================================================
*/

static bool _CheckAlignment(const void* ptr, size_t alignment)
{
    if (alignment == 0)
        return true;

    if (_Round((uint64_t)ptr, alignment) == (uint64_t)ptr)
        return true;

    return false;
}

/*
**==============================================================================
**
** _GetBlockSize() -- get total size of a block
**
**==============================================================================
*/

OE_INLINE size_t _GetBlockSize(const Header* block)
{
    return sizeof(Header) + block->size + sizeof(Trailer);
}

/*
**==============================================================================
**
** _SplitBlock()
**
**     Split a block into two adjacent blocks. Return the excess block.
**
**==============================================================================
*/

OE_INLINE Header* _SplitBlock(
    Header* block, 
    size_t size)
{
    Header* excess = NULL;

    /* Reject bad parameters */
    if (!block || !size || (size % sizeof(uint64_t)))
        return NULL;

    /* Get the size of the block to be split */
    size_t bsize = _GetBlockSize(block);

    /* Calculate total bytes required by new block */
    size_t r = sizeof(Header) + size + sizeof(Trailer);

    /* If not enough memory for both blocks */
    if (r + MIN_BLOCK_SIZE > bsize)
        return NULL;

    /* Initialize the new block */
    _InitHeader(block, true, 0, size);
    _InitTrailer(_GetTrailer(block), true, 0, size);

    /* Initialize the excess block */
    excess = (Header*)((uint8_t*)block + r);
    size_t esize = bsize - r - sizeof(Header) - sizeof(Trailer);
    _InitHeader(excess, false, 0, esize);
    _InitTrailer(_GetTrailer(excess), false, 0, esize);

    return excess;
}

/*
**==============================================================================
**
** _JoinBlocks()
**
**     Join two adjacent blocks into one.
**
**==============================================================================
*/

static Header* _JoinBlocks(Header* left, Header* right)
{
    if (!left || !right)
        return NULL;

    /* Calculate size of the joined block */
    size_t bsize = _GetBlockSize(left) + _GetBlockSize(right);

    /* Calculate new size of user memory */
    size_t usize = bsize - sizeof(Header) - sizeof(Trailer);

    /* Intialize the block for the free list */
    _InitBlock(left, false, 0, usize);

    return left;
}

/*
**==============================================================================
**
** _SplitAndReturnUnused()
**
**     Return the unused portion of the given block to the free list.
**
**==============================================================================
*/

static int _SplitAndReturnUnused(
    Header* block, 
    size_t alignment, 
    size_t size, 
    bool lock)
{
    size_t newBlockSize = sizeof(Header) + size + sizeof(Trailer);
    size_t blockSize = _GetBlockSize(block);
    size_t excessBlockSize = blockSize - newBlockSize;

    if (blockSize < newBlockSize)
        return -1;

    if (excessBlockSize >= MIN_BLOCK_SIZE)
    {
        Header* excess = _SplitBlock(block, size); 
        if (!excess)
            return -1;

        if (lock)
            OE_SpinLock(&_lock);

        /* Coalesce neighbors */
        {
            /* Join block with left neighbor if free */
            {
                Header* left = _GetLeftNeighbor(excess);

                if (left)
                    excess = _JoinBlocks(left, excess);
            }

            /* Join excess with right neighbor if free */
            {
                Header* right = _GetRightNeighbor(excess);

                if (right)
                    excess = _JoinBlocks(excess, right);
            }

            /* Reinitialize the excess block for the free list */
            _InitBlock(excess, false, 0, excess->size);

            /* Insert block into the free list */
            _FreeListPut(excess);
        }

        if (lock)
            OE_SpinUnlock(&_lock);
    }
    else
    {
        _InitBlock(block, true, alignment, block->size);
    }

    return 0;
}
/*
**==============================================================================
**
** OE_GetMallocStats()
**
**==============================================================================
*/

static uint64_t _numMallocs;
static uint64_t _numFrees;

void OE_GetMallocStats(OE_MallocStats* stats)
{
    if (!stats)
        return;

    /* Heap stats */
    stats->heapSize = _end - _base;
    stats->heapUsed = _ptr - _base;
    stats->heapAvailable = _end - _ptr;
    stats->heapUsage = ((float)stats->heapUsed / stats->heapSize) * 100.0;

    /* Free list stats */
    stats->freeListSize = _FreeListSize();

    /* Function call stats */
    stats->numMallocs = OE_AtomicRead(&_numMallocs);
    stats->numFrees = OE_AtomicRead(&_numFrees);
}

/*
**==============================================================================
**
** OE_MEMALIGN()
**
**     Allocate a block aligned on the given boundary with the following 
**     layout:
**
**                  <---------- size ---------->
**                  <--- offset -->
**         [HEADER] [.......HEADER] [USERMEMORY] [TRAILER]
**                                  ^
**                                 ptr
**
**     Note that aligned blocks have a second header immediately preceding 
**     the user bytes.
**
**==============================================================================
*/

void* OE_MEMALIGN(size_t alignment, size_t size)
{
    void* ptr = NULL;

    _Initialize();

    /* Fail if OE_InitMalloc() was never called */
    if (!_initialized || !size)
        return NULL;

    /* Round size up to the next multiple of the word size */
    size = _Round(size, sizeof(uint64_t));

    /* Ajust size to make room for alignment */
    if (alignment)
    {
        /* Fail if alignment is not zero or a power of two */
        if (!_IsPow2(alignment))
            return NULL;

        /* Round alignment up to word boundary */
        if (alignment < sizeof(uint64_t))
            alignment = sizeof(uint64_t);

        /* Increase size to make room for alignment */
        size += alignment;
    }

    /* Look for suitable block on the free list */
    OE_SpinLock(&_lock);
    {
        Header* block = _FreeListGet(size);

        if (block)
        {
            size_t bsize = _GetBlockSize(block);
            size_t nsize = sizeof(Header) + size + sizeof(Trailer);
            size_t esize = bsize - nsize;

            if (esize >= MIN_BLOCK_SIZE)
            {
                Header* excess = _SplitBlock(block, size);
                ASSERT(excess);
                ASSERT(_GetBlockSize(excess) == esize);
                ASSERT(_GetBlockSize(block) == nsize);
                _FreeListPut(excess);

                /* Initialize the alignment */
                _InitBlock(block, true, alignment, size);
            }
            else
            {
                /* Use slightly oversized block */
                _InitBlock(block, true, alignment, block->size);
            }

            ptr = _BlockToPtr(block);
            ASSERT(_CheckBusyBlock(ptr));
        }
    }
    OE_SpinUnlock(&_lock);

    /* If no block found on free list, then reserved one from heap */
    if (!ptr)
    {
        /* Calculate the total size of block including header and trailer */
        size_t tsize = sizeof(Header) + size + sizeof(Trailer);

        /* Reserve the memory */
        uint8_t* block;
        {
            OE_SpinLock(&_lock);
            block = (uint8_t*)_Reserve(tsize);
            OE_SpinUnlock(&_lock);

            if (!block)
                return NULL;
        }

        /* Initialize the block */
        _InitBlock(block, true, alignment, size);

        ASSERT(_IsLastBlock(block));

        ptr = _BlockToPtr(block);
    }

    assert(_CheckBusyBlock(ptr));
    assert(_CheckAlignment(ptr, alignment));

    OE_AtomicIncrement(&_numMallocs);

    return ptr;
}

/*
**==============================================================================
**
** OE_MALLOC()
**
**     Allocate a block with the following layout:
**
**                  <-- size -->
**         [HEADER] [USERMEMORY] [TRAILER]
**                  ^
**                 ptr
**
**     Return address following the header.
**
**==============================================================================
*/

void* OE_MALLOC(size_t size)
{
    return OE_MEMALIGN(0, size);
}

/*
**==============================================================================
**
** OE_CALLOC()
**
**==============================================================================
*/

void* OE_CALLOC(size_t nmemb, size_t size)
{
    void* ptr = OE_MEMALIGN(0, nmemb * size);

    if (ptr)
        memset(ptr, 0, nmemb * size);

    return ptr;
}

/*
**==============================================================================
**
** OE_FREE()
**
**     Free the given memory block.
**
**==============================================================================
*/

void OE_FREE(void* ptr_)
{
    uint8_t* ptr = (uint8_t*)ptr_;

    _Initialize();

    if (!ptr)
        return;

    if (!_CheckBusyBlock(ptr))
    {
        ASSERT(0);
        return;
    }

    /* Get the block from this pointer */
    Header* block = _PtrToBlock(ptr);
    if (!block)
    {
        ASSERT(0);
        return;
    }

    OE_SpinLock(&_lock);
    {
        /* Join block with left neighbor if free */
        {
            Header* left = _GetLeftNeighbor(block);

            if (left)
                block = _JoinBlocks(left, block);
        }

        /* Join block with right neighbor if free */
        {
            Header* right = _GetRightNeighbor(block);

            if (right)
                block = _JoinBlocks(block, right);
        }

        /* Reinitialize the block for the free list */
        _InitBlock(block, false, 0, block->size);

        /* Insert block into the free list */
        _FreeListPut(block);
    }
    OE_SpinUnlock(&_lock);

    OE_AtomicIncrement(&_numFrees);
}

/*
**==============================================================================
**
** OE_REALLOC()
**
**==============================================================================
*/

void* OE_REALLOC(void* ptr, size_t size)
{
    Header* block;
    size_t oldSize;

    _Initialize();

    if (!ptr)
        return OE_MALLOC(size);

    if (!_CheckBusyBlock(ptr) || !(block = _PtrToBlock(ptr)))
    {
        ASSERT(0);
        return NULL;
    }

    /* If this is an aligned block (rare), then use less efficient method */
    if (block->offset)
    {
        const void* alignedPtr = _BlockToPtr(block);
        size_t alignedSize = block->size - block->offset;
        void* p;

        if (!alignedPtr)
        {
            ASSERT(0);
            return NULL;
        }

        if (!(p = OE_MALLOC(size)))
            return NULL;

        if (alignedSize < size)
            memcpy(p, alignedPtr, alignedSize);
        else
            memcpy(p, alignedPtr, size);

        OE_FREE(ptr);

        return p;
    }

    /* Round size up to the next multiple of the word size */
    size = _Round(size, sizeof(uint64_t));

    /* Save the old size */
    oldSize = block->size;

    /* Calcualte the total size of the new block */
    size_t newBlockSize = sizeof(Trailer) + size + sizeof(Header);

    /* If block will be smaller, else it will be bigger */
    if (size < oldSize)
    {
        /* Return any unused porition to the free list */
        if (_SplitAndReturnUnused(block, 0, size, true) != 0)
            ASSERT(0);
    }
    else if (size > oldSize)
    {
        /* Join block with right neighbor */
        OE_SpinLock(&_lock);
        {
            Header* right = _GetRightNeighbor(block);

            if (right)
            {
                block = _JoinBlocks(block, right);

                size_t blockSize = _GetBlockSize(block);

                /* Return any unused portion */
                if (blockSize > newBlockSize)
                {
                    if (_SplitAndReturnUnused(block, 0, size, false) != 0)
                        ASSERT(0);
                }
            }
        }
        OE_SpinUnlock(&_lock);

        /* If block still not big enough, then allocate a new one */
        if (block->size < size)
        {
            void* p;

            if (!(p = OE_MALLOC(size)))
                return NULL;

            memcpy(p, ptr, oldSize);
            block = _PtrToBlock(p);
            OE_FREE(ptr);
        }
    }

    ptr = _BlockToPtr(block);
    ASSERT(_CheckBusyBlock(ptr));

    return ptr;
}

/*
**==============================================================================
**
** posix_memalign()
**
**==============================================================================
*/

int posix_memalign(void** memptr, size_t alignment, size_t size)
{
    /* ATTN: set errno here! */

    if (!*memptr)
        return -1;

    *memptr = OE_MEMALIGN(alignment, size);
    return 0;
}
