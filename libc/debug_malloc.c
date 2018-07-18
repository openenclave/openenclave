// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(OE_USE_DEBUG_MALLOC)

#define USE_DL_PREFIX
#include "debug_malloc.h"
#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/utils.h>
#include <openenclave/internal/backtrace.h>
#include "../3rdparty/dlmalloc/dlmalloc/malloc.h"

/*
**==============================================================================
**
** Debug allocator:
**
**     This allocator keeps in-use blocks on a linked list, so that memory
**     leaks can be detected by dumping this list before program exit.
**
**     Each block has the following layout.
**
**         [padding] [header] [user-data] [footer]
**
**     The padding is only used when a non-zero alignment is passed to memaign()
**     or posix_memalign(). The padding ensures that the user data will have
**     the desired alignmnent (in spite of the preceding header).
**
**     The oe_debug_malloc_dump() function below prints a backtrace for each
**     in-use memory block.
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
    uint64_t size;

    /* Return addresses obtained by oe_backtrace() */
    void* addrs[OE_BACKTRACE_MAX];
    uint64_t num_addrs;

    /* Contains HEADER_MAGIC1 */
    uint64_t magic2;

    /* User data */
    uint8_t data[];
};

OE_STATIC_ASSERT(sizeof(header_t) == 56 + (OE_BACKTRACE_MAX * sizeof(uint64_t)));

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

OE_ALWAYS_INLINE
void _init_block(header_t* header, size_t alignment, size_t size)
{
    /* Initialize the header */
    header->magic1 = HEADER_MAGIC1;
    header->next = NULL;
    header->prev = NULL;
    header->alignment = alignment;
    header->size = size;
    header->num_addrs = oe_backtrace(header->addrs, OE_BACKTRACE_MAX);
    header->magic2 = HEADER_MAGIC2;

    /* Initialize the footer */
    _get_footer(header->data)->magic = FOOTER_MAGIC;
}

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

static void _malloc_dump_ocall(uint64_t size, void* addrs[], int num_addrs)
{
    oe_malloc_dump_args_t* args = NULL;
    const uint32_t flags = OE_OCALL_FLAG_NOT_REENTRANT;

    if (!(args = oe_host_malloc(sizeof(oe_malloc_dump_args_t))))
        goto done;

    args->size = size;
    oe_memcpy(args->addrs, addrs, sizeof(void*) * OE_COUNTOF(args->addrs));
    args->num_addrs = num_addrs;

    if (oe_ocall(OE_OCALL_MALLOC_DUMP, (uint64_t)args, NULL, flags) != OE_OK)
        goto done;

done:

    if (args)
        oe_host_free(args);
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

    if (!(block = dlmalloc(block_size)))
        return NULL;

    /* Fill block with 0xAA (Allocated) bytes */
    oe_memset(block, 0xAA, block_size);

    header_t* header = (header_t*)block;
    _init_block(header, 0, size);
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
        oe_memset(block, 0xDD, block_size);

        dlfree(block);
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

    oe_memset(ptr, 0, total_size);

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
            oe_memcpy(new_ptr, ptr, header->size);
        else
            oe_memcpy(new_ptr, ptr, size);

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

    if (!(block = dlmemalign(alignment, block_size)))
        return NULL;

    header = (header_t*)((uint8_t*)block + padding_size);

    _init_block(header, alignment, size);
    _check_block(header);
    _list_insert(&_list, header);

    return header->data;
}

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    if (!memptr)
        return EINVAL;

    if (!(*memptr = oe_debug_memalign(alignment, size)))
        return ENOMEM;

    return 0;
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
            _malloc_dump_ocall(p->size, p->addrs, p->num_addrs);

        oe_host_printf("\n");
    }

    if (need_lock)
        oe_spin_unlock(&_spin);
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
