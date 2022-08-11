// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "debugmalloc.h"
#include <openenclave/advanced/allocator.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/debugmalloc.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/types.h>
#include <openenclave/internal/utils.h>
#include "core_t.h" /* for oe_edger8r_secure_unserialize */

/* Flags to control runtime behavior. */
bool oe_use_debug_malloc = true;
bool oe_use_debug_malloc_memset = true;

/* Flags to define the local tracking state. */
bool oe_use_debug_malloc_tracking = false;
/* Session number to identify the session of local tracking. */
int32_t oe_debug_malloc_session_number = 0;

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

    /* Option if current object is tracked */
    int32_t session_number;

    /* Padding to make header a multiple of 16 */
    uint8_t padding[4];

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
#define INIT_BLOCK(HEADER, ALIGNMENT, SIZE)                                    \
    do                                                                         \
    {                                                                          \
        HEADER->magic1 = HEADER_MAGIC1;                                        \
        HEADER->next = NULL;                                                   \
        HEADER->prev = NULL;                                                   \
        HEADER->alignment = ALIGNMENT;                                         \
        HEADER->size = SIZE;                                                   \
        HEADER->num_addrs =                                                    \
            (uint64_t)oe_backtrace(HEADER->addrs, OE_BACKTRACE_MAX);           \
        HEADER->session_number =                                               \
            oe_use_debug_malloc_tracking ? oe_debug_malloc_session_number : 0; \
        HEADER->magic2 = HEADER_MAGIC2;                                        \
        _get_footer(HEADER->data)->magic = FOOTER_MAGIC;                       \
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
    char** symbols = NULL;

    /* Get symbol names for these addresses */
    if (!(symbols = oe_backtrace_symbols(addrs, num_addrs)))
        goto done;

    oe_host_printf("%llu bytes\n", OE_LLX(size));

    for (int i = 0; i < num_addrs; i++)
        oe_host_printf("%s(): %p\n", symbols[i], addrs[i]);

    oe_host_printf("\n");

done:
    oe_backtrace_symbols_free(symbols);
}

static void _dump(bool need_lock)
{
    bool secure_unserialize_enabled = false;
    list_t* list = &_list;

    if (need_lock)
        oe_spin_lock(&_spin);

    /* Temporarily disable the oe_edger8r_secure_unserialize (if set)
     * to avoid using malloc in the OCALL marshalling code
     * that cause deadlock on _spin when debug malloc is enabled. */
    if (oe_edger8r_secure_unserialize)
    {
        secure_unserialize_enabled = true;
        oe_edger8r_secure_unserialize = false;
    }

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

    /* Re-enable oe_edger8r_secure_unserialize if needed */
    if (secure_unserialize_enabled)
        oe_edger8r_secure_unserialize = true;

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

    if (!(block = oe_allocator_malloc(block_size)))
        return NULL;

    /* Fill block with 0xAA (Allocated) bytes */
    if (oe_use_debug_malloc_memset)
    {
        oe_memset_s(block, block_size, 0xAA, block_size);
    }

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

        oe_allocator_free(block);
    }
}

void* oe_debug_calloc(size_t nmemb, size_t size)
{
    void* ptr;

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

        // oe_debug_malloc sets errno correctly.
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

int oe_debug_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    const size_t padding_size = _get_padding_size(alignment);
    const size_t block_size = _calculate_block_size(alignment, size);
    void* block = NULL;
    header_t* header = NULL;
    int ret = 0;

    if ((ret = oe_allocator_posix_memalign(&block, alignment, block_size)) != 0)
        return ret;

    header = (header_t*)((uint8_t*)block + padding_size);

    INIT_BLOCK(header, alignment, size);
    _check_block(header);
    _list_insert(&_list, header);
    *memptr = header->data;

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

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

static oe_allocation_failure_callback_t _failure_callback;

void oe_set_allocation_failure_callback(
    oe_allocation_failure_callback_t function)
{
    _failure_callback = function;
}

void* oe_malloc(size_t size)
{
    void* p = NULL;
    if (oe_use_debug_malloc)
    {
        p = oe_debug_malloc(size);
    }
    else
    {
        p = oe_allocator_malloc(size);
    }

    if (!p && size)
    {
        oe_errno = OE_ENOMEM;
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void oe_free(void* ptr)
{
    if (oe_use_debug_malloc)
    {
        oe_debug_free(ptr);
    }
    else
    {
        oe_allocator_free(ptr);
    }
}

void* oe_calloc(size_t nmemb, size_t size)
{
    void* p = NULL;

    if (_check_multiply_overflow(nmemb, size))
        goto done;

    if (oe_use_debug_malloc)
    {
        p = oe_debug_calloc(nmemb, size);
    }
    else
    {
        p = oe_allocator_calloc(nmemb, size);
    }

done:
    if (!p && nmemb && size)
    {
        oe_errno = OE_ENOMEM;
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, nmemb * size);
    }

    return p;
}

void* oe_realloc(void* ptr, size_t size)
{
    void* p = NULL;
    if (oe_use_debug_malloc)
    {
        p = oe_debug_realloc(ptr, size);
    }
    else
    {
        p = oe_allocator_realloc(ptr, size);
    }

    if (!p && size)
    {
        oe_errno = OE_ENOMEM;
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return p;
}

void* oe_memalign(size_t alignment, size_t size)
{
    void* ptr = NULL;

    if (!oe_is_pow2(alignment))
        oe_errno = OE_EINVAL;
    else
    {
        if (alignment < sizeof(void*))
            alignment = sizeof(void*);
        int r = oe_posix_memalign(&ptr, alignment, size);
        if (r)
            oe_errno = r;
    }

    return ptr;
}

int oe_posix_memalign(void** memptr, size_t alignment, size_t size)
{
    int rc = -1;

    if (!memptr)
        return OE_EINVAL;

    if (!oe_is_ptrsize_multiple(alignment) || !oe_is_pow2(alignment))
        return OE_EINVAL;

    if (oe_use_debug_malloc)
        rc = oe_debug_posix_memalign(memptr, alignment, size);
    else
        rc = oe_allocator_posix_memalign(memptr, alignment, size);

    if (rc != 0 && size)
    {
        if (_failure_callback)
            _failure_callback(__FILE__, __LINE__, __FUNCTION__, size);
    }

    return rc;
}

size_t oe_malloc_usable_size(void* ptr)
{
    if (oe_use_debug_malloc)
    {
        return oe_debug_malloc_usable_size(ptr);
    }
    else
    {
        return oe_allocator_malloc_usable_size(ptr);
    }
}

oe_result_t oe_check_memory_leaks(void)
{
    if (!oe_disable_debug_malloc_check && oe_debug_malloc_check() != 0)
        return OE_MEMORY_LEAK;
    return OE_OK;
}

oe_result_t oe_debug_malloc_tracking_start(void)
{
    oe_result_t result = OE_UNEXPECTED;

    oe_spin_lock(&_spin);
    if (!oe_use_debug_malloc_tracking)
    {
        oe_use_debug_malloc_tracking = true;
        ++oe_debug_malloc_session_number;
        result = OE_OK;
    }
    oe_spin_unlock(&_spin);

    return result;
}

oe_result_t oe_debug_malloc_tracking_stop(void)
{
    oe_result_t result = OE_UNEXPECTED;

    oe_spin_lock(&_spin);
    if (oe_use_debug_malloc_tracking)
    {
        oe_use_debug_malloc_tracking = false;
        result = OE_OK;
    }
    oe_spin_unlock(&_spin);

    return result;
}

static oe_result_t _copy_frames(
    header_t* p,
    char** str,
    size_t* size,
    size_t* index)
{
    oe_result_t result = OE_FAILURE;
    char** symbols = NULL;

    if (!(symbols = oe_backtrace_symbols(p->addrs, (int)(p->num_addrs))))
    {
        goto done;
    }

    for (uint64_t i = 0; i < p->num_addrs; i++)
    {
        size_t length_s = oe_strlen(symbols[i]);
        size_t length_a = sizeof(p->addrs[i]) * 2;
        size_t length = length_s + length_a + 6;

        if (*index + length >= *size)
        {
            while (*index + length >= *size)
            {
                *size *= 2;
            }

            *str = oe_realloc(*str, *size);
            if (*str == NULL)
            {
                result = OE_ENOMEM;
                goto done;
            }
        }

        oe_snprintf(
            *str + *index, length, "%s(): %p\n", symbols[i], p->addrs[i]);
        *index = oe_strlen(*str);
    }

    (*str)[(*index)++] = '\n';
    (*str)[*index] = '\0';

    result = OE_OK;

done:
    oe_backtrace_symbols_free(symbols);

    return result;
}

oe_result_t oe_debug_malloc_tracking_report(
    uint64_t* out_object_count,
    char** report)
{
    bool secure_unserialize_enabled = false;
    oe_result_t result = OE_OK;
    uint64_t count = 0;

    size_t index = 0;
    size_t length = 4096;
    char* report_string = oe_malloc(length);
    if (!report_string)
    {
        result = OE_ENOMEM;
        goto done;
    }
    report_string[0] = '\0';

    list_t* list = &_list;
    oe_spin_lock(&_spin);

    /* Temporarily disable the oe_edger8r_secure_unserialize (if set)
     * to avoid using malloc in the OCALL marshalling code
     * that cause deadlock on _spin when debug malloc is enabled. */
    if (oe_edger8r_secure_unserialize)
    {
        secure_unserialize_enabled = true;
        oe_edger8r_secure_unserialize = false;
    }

    {
        for (header_t* p = list->head; p; p = p->next)
        {
            if (p->session_number)
            {
                count++;
                result = _copy_frames(p, &report_string, &length, &index);
                if (result != OE_OK)
                {
                    goto done;
                }
            }
        }
    }

    /* Re-enable the oe_edger8r_secure_unserialize if needed */
    if (secure_unserialize_enabled)
        oe_edger8r_secure_unserialize = true;

    oe_spin_unlock(&_spin);

    length = index + 1;
    report_string = oe_realloc(report_string, length);
    if (!report_string)
    {
        result = OE_ENOMEM;
        goto done;
    }

    *out_object_count = count;
    *report = report_string;

done:
    oe_spin_unlock(&_spin);
    return result;
}
