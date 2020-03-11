// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "debugmalloc.h"
#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>

#if defined(OE_USE_DEBUG_MALLOC)

#include "oe_nodebug_alloc.h"

/*
**==============================================================================
**
** Debug allocator:
**
**     This allocator checks for the following memory errors.
**
**         (1) Leaked blocks on program exit.
**         (2) Memory overwrites just before/after the block.
**         (3) Assuming blocks are zero filled (fills new blocks with 0xAA).
**         (3) Use of free memory (fills freed blocks with 0xDD).
**
**     This allocator keeps in-use blocks on a linked list. Each block has the
**     following layout.
**
**         [padding] [header] [user-data] [footer]
**
**     The padding is applied by memalign() when the alignment is non-zero.
**
**==============================================================================
*/

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

#define HEADER_MAGIC1 0x185f0447c6f5440f
#define HEADER_MAGIC2 0x56cfbed5df804061
#define FOOTER_MAGIC 0x8bb6dcd8f4724bc7

typedef struct header header_t;

struct header
{
    /* Contains HEADER_MAGIC1 */
    uint64_t magic1;

    /* Headers are kept on a doubly-linked list */
    header_t* next;
    header_t* prev;

    /* The alignment passed to memalign() or zero */
    uint64_t alignment;

    /* Size of user memory */
    size_t size;

    /* Return addresses obtained by oe_backtrace() */
    void* addrs[OE_BACKTRACE_MAX];
    uint64_t num_addrs;

    /* Padding to make header a multiple of 16 */
    uint64_t padding;

    /* Contains HEADER_MAGIC2 */
    uint64_t magic2;

    /* User data */
    uint8_t data[];
};

/* Verify that the sizeof(header_t) is a multiple of 16 */
OE_STATIC_ASSERT(sizeof(header_t) % 16 == 0);

typedef struct footer footer_t;

struct footer
{
    /* Contains FOOTER_MAGIC */
    uint64_t magic;
};

OE_STATIC_ASSERT(sizeof(footer_t) == sizeof(uint64_t));

/* Get a pointer to the header from the user data */
OE_INLINE header_t* _get_header(void* ptr)
{
    return (header_t*)((uint8_t*)ptr - sizeof(header_t));
}

/* Get a pointer to the footer from the user data */
OE_INLINE footer_t* _get_footer(void* ptr)
{
    header_t* header = _get_header(ptr);
    size_t rsize = oe_round_up_to_multiple(header->size, sizeof(uint64_t));
    return (footer_t*)((uint8_t*)ptr + rsize);
}

/* Use a macro so the function name will not appear in the backtrace */
#define INIT_BLOCK(HEADER, ALIGNMENT, SIZE)                          \
    do                                                               \
    {                                                                \
        HEADER->magic1 = HEADER_MAGIC1;                              \
        HEADER->next = NULL;                                         \
        HEADER->prev = NULL;                                         \
        HEADER->alignment = ALIGNMENT;                               \
        HEADER->size = SIZE;                                         \
        HEADER->num_addrs =                                          \
            (uint64_t)oe_backtrace(HEADER->addrs, OE_BACKTRACE_MAX); \
        HEADER->magic2 = HEADER_MAGIC2;                              \
        _get_footer(HEADER->data)->magic = FOOTER_MAGIC;             \
    } while (0)

/* Assert and abort if magic numbers are wrong */
static void _check_block(header_t* header)
{
    if (header->magic1 != HEADER_MAGIC1)
    {
        oe_assert("_check_block() panic" == NULL);
        oe_abort();
    }

    if (header->magic2 != HEADER_MAGIC2)
    {
        oe_assert("_check_block() panic" == NULL);
        oe_abort();
    }

    if (_get_footer(header->data)->magic != FOOTER_MAGIC)
    {
        oe_assert("_check_block() panic" == NULL);
        oe_abort();
    }
}

/* Calculate the padding size for a block with this aligment */
OE_INLINE size_t _get_padding_size(size_t alignment)
{
    if (!alignment)
        return 0;

    const size_t header_size = sizeof(header_t);
    return oe_round_up_to_multiple(header_size, alignment) - header_size;
}

OE_INLINE void* _get_block_address(void* ptr)
{
    header_t* header = _get_header(ptr);
    const size_t padding_size = _get_padding_size(header->alignment);
    return (uint8_t*)ptr - sizeof(header_t) - padding_size;
}

OE_INLINE size_t _calculate_block_size(size_t alignment, size_t size)
{
    size_t r = 0;
    r += _get_padding_size(alignment);
    r += sizeof(header_t);
    r += oe_round_up_to_multiple(size, sizeof(uint64_t));
    r += sizeof(footer_t);

    /* Check for overflow */
    if (r < size)
        return OE_SIZE_MAX;

    return r;
}

OE_INLINE size_t _get_block_size(void* ptr)
{
    const header_t* header = _get_header(ptr);
    return _calculate_block_size(header->alignment, header->size);
}

/* Doubly-linked list of headers */
typedef struct _list
{
    header_t* head;
    header_t* tail;
} list_t;

static list_t _list = {NULL, NULL};
static oe_spinlock_t _spin = OE_SPINLOCK_INITIALIZER;

static void _list_insert(list_t* list, header_t* header)
{
    oe_spin_lock(&_spin);
    {
        if (list->head)
        {
            header->prev = NULL;
            header->next = list->head;
            list->head->prev = header;
            list->head = header;
        }
        else
        {
            header->prev = NULL;
            header->next = NULL;
            list->head = header;
            list->tail = header;
        }
    }
    oe_spin_unlock(&_spin);
}

static void _list_remove(list_t* list, header_t* header)
{
    oe_spin_lock(&_spin);
    {
        if (header->next)
            header->next->prev = header->prev;

        if (header->prev)
            header->prev->next = header->next;

        if (header == list->head)
            list->head = header->next;
        else if (header == list->tail)
            list->tail = header->prev;
    }
    oe_spin_unlock(&_spin);
}

OE_INLINE bool _check_multiply_overflow(size_t x, size_t y)
{
    if (x == 0 || y == 0)
        return false;

    size_t product = x * y;

    if (x == product / y)
        return false;

    return true;
}

static void _malloc_dump(size_t size, void* addrs[], int num_addrs)
{
    char** syms = NULL;

    /* Get symbol names for these addresses */
    if (!(syms = oe_backtrace_symbols(addrs, num_addrs)))
        goto done;

    oe_host_printf("%llu bytes\n", OE_LLX(size));

    for (int i = 0; i < num_addrs; i++)
        oe_host_printf("%s(): %p\n", syms[i], addrs[i]);

    oe_host_printf("\n");

done:

    if (syms)
        oe_backtrace_symbols_free(syms);
}

static void _dump(bool need_lock)
{
    list_t* list = &_list;

    if (need_lock)
        oe_spin_lock(&_spin);

    {
        size_t blocks = 0;
        size_t bytes = 0;

        /* Count bytes allocated and blocks still in use */
        for (header_t* p = list->head; p; p = p->next)
        {
            blocks++;
            bytes += p->size;
        }

        oe_host_printf(
            "=== %s(): %zu bytes in %zu blocks\n", __FUNCTION__, bytes, blocks);

        for (header_t* p = list->head; p; p = p->next)
            _malloc_dump(p->size, p->addrs, (int)p->num_addrs);

        oe_host_printf("\n");
    }

    if (need_lock)
        oe_spin_unlock(&_spin);
}

/*
**==============================================================================
**
** Public definitions:
**
**==============================================================================
*/

void* oe_debug_malloc(size_t size)
{
    void* block;
    const size_t block_size = _calculate_block_size(0, size);

    if (!(block = oe_nodebug_malloc(block_size)))
        return NULL;

    /* Fill block with 0xAA (Allocated) bytes */
    oe_memset_s(block, block_size, 0xAA, block_size);

    header_t* header = (header_t*)block;
    INIT_BLOCK(header, 0, size);
    _check_block(header);
    _list_insert(&_list, header);

    return header->data;
}

void oe_debug_free(void* ptr)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        _check_block(header);
        _list_remove(&_list, header);

        /* Fill the whole block with 0xDD (Deallocated) bytes */
        void* block = _get_block_address(ptr);
        size_t block_size = _get_block_size(ptr);
        oe_memset_s(block, block_size, 0xDD, block_size);

        oe_nodebug_free(block);
    }
}

void* oe_debug_calloc(size_t nmemb, size_t size)
{
    void* ptr;

    if (_check_multiply_overflow(nmemb, size))
        return NULL;

    const size_t total_size = nmemb * size;

    if (!(ptr = oe_debug_malloc(total_size)))
        return NULL;

    oe_memset_s(ptr, total_size, 0, total_size);

    return ptr;
}

void* oe_debug_realloc(void* ptr, size_t size)
{
    if (ptr)
    {
        header_t* header = _get_header(ptr);
        void* new_ptr;

        _check_block(header);

        /* If the size is the same, just return the pointer */
        if (header->size == size)
            return ptr;

        if (!(new_ptr = oe_debug_malloc(size)))
            return NULL;

        if (size > header->size)
        {
            if (oe_memcpy_s(new_ptr, size, ptr, header->size) != OE_OK)
                return NULL;
        }
        else
        {
            if (oe_memcpy_s(new_ptr, size, ptr, size) != OE_OK)
                return NULL;
        }

        oe_debug_free(ptr);

        return new_ptr;
    }
    else
    {
        return oe_debug_malloc(size);
    }
}

void* oe_debug_memalign(size_t alignment, size_t size)
{
    const size_t padding_size = _get_padding_size(alignment);
    const size_t block_size = _calculate_block_size(alignment, size);
    void* block;
    header_t* header;

    if (!(block = oe_nodebug_memalign(alignment, block_size)))
        return NULL;

    header = (header_t*)((uint8_t*)block + padding_size);

    INIT_BLOCK(header, alignment, size);
    _check_block(header);
    _list_insert(&_list, header);

    return header->data;
}

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    if (!memptr)
        return OE_EINVAL;

    if (!oe_is_ptrsize_multiple(alignment) || !oe_is_pow2(alignment))
        return OE_EINVAL;

    if (!(*memptr = oe_debug_memalign(alignment, size)))
        return OE_ENOMEM;

    return 0;
}

size_t oe_debug_malloc_usable_size(void* ptr)
{
    if (!ptr)
        return 0;
    return _get_header(ptr)->size;
}

void oe_debug_malloc_dump(void)
{
    _dump(true);
}

size_t oe_debug_malloc_check(void)
{
    list_t* list = &_list;
    size_t count = 0;

    oe_spin_lock(&_spin);
    {
        for (header_t* p = list->head; p; p = p->next)
            count++;

        if (count)
        {
            _dump(false);

            for (header_t* p = list->head; p; p = p->next)
                _check_block(p);
        }
    }
    oe_spin_unlock(&_spin);

    return count;
}

#endif /* defined(OE_USE_DEBUG_MALLOC) */
