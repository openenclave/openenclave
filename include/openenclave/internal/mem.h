// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _MEM_H
#define _MEM_H

#include <limits.h>
#include <openenclave/internal/defs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
#define MEM_INLINE inline
#else
#define MEM_INLINE static __inline
#endif

#ifdef __GNUC__
#define MEM_PRINTF_FORMAT(N, M) __attribute__((format(printf, N, M)))
#else
#define MEM_PRINTF_FORMAT(N, M)
#endif

/* mem_t.__magic */
#define MEM_MAGIC 0x2dc62e7f

/* mem_t.__cap */
#ifndef MEM_MIN_CAP
#define MEM_MIN_CAP 32
#endif

#define MEM_NPOS ((size_t)-1)

/* mem_t.__type */
typedef enum _mem_type_t
{
    MEM_TYPE_NONE = 1,
    MEM_TYPE_DYNAMIC = 2,
    MEM_TYPE_STATIC = 4,
    __MEM_TYPE_MAX = UINT_MAX,
} mem_type_t;

OE_STATIC_ASSERT(sizeof(mem_type_t) == sizeof(unsigned int));

typedef struct _mem_t
{
    unsigned int __magic;
    mem_type_t __type;
    unsigned char* __ptr;
    size_t __size;
    size_t __cap;
} mem_t;

#define MEM_NULL_INIT \
    {                 \
        0, 0, NULL, 0 \
    }

#define MEM_DYNAMIC_INIT                     \
    {                                        \
        MEM_MAGIC, MEM_TYPE_DYNAMIC, NULL, 0 \
    }

MEM_INLINE int mem_ok(const mem_t* mem)
{
    return mem && mem->__magic == MEM_MAGIC;
}

/* Dynamic initializer */
MEM_INLINE int mem_dynamic(mem_t* mem, void* ptr, size_t size, size_t cap)
{
    if (!mem || (ptr && cap == 0))
        return -1;

    mem->__magic = MEM_MAGIC;
    mem->__type = MEM_TYPE_DYNAMIC;
    mem->__ptr = (unsigned char*)ptr;
    mem->__size = size;
    mem->__cap = cap;

    return 0;
}

/* Static initializer */
MEM_INLINE int mem_static(mem_t* mem, void* ptr, size_t cap)
{
    if (!mem || !ptr || cap == 0)
        return -1;

    mem->__magic = MEM_MAGIC;
    mem->__type = MEM_TYPE_STATIC;
    mem->__ptr = (unsigned char*)ptr;
    mem->__size = 0;
    mem->__cap = cap;

    return 0;
}

/* Dynamic destructor */
MEM_INLINE int mem_free(mem_t* mem)
{
    if (!mem_ok(mem))
        return -1;

    if (mem->__ptr)
        free(mem->__ptr);

    memset(mem, 0, sizeof(mem_t));

    return 0;
}

/* Steal the internal heap allocation (ends the lifetime of the object) */
MEM_INLINE void* mem_steal(mem_t* mem)
{
    void* ptr;

    if (!mem_ok(mem))
        return NULL;

    if (mem->__type != MEM_TYPE_DYNAMIC)
        return NULL;

    ptr = mem->__ptr;
    memset(mem, 0, sizeof(mem_t));

    return ptr;
}

MEM_INLINE mem_type_t mem_type(const mem_t* mem)
{
    if (!mem_ok(mem))
        return MEM_TYPE_NONE;

    return mem->__type;
}

/* Return const pointer */
MEM_INLINE const void* mem_ptr(const mem_t* mem)
{
    if (!mem_ok(mem))
        return NULL;

    return mem->__ptr;
}

/* Return pointer to end of buffer */
MEM_INLINE const void* mem_end(const mem_t* mem)
{
    if (!mem_ok(mem))
        return NULL;

    return mem->__ptr + mem->__size;
}

/* Return const pointer */
MEM_INLINE const void* mem_ptr_at(const mem_t* mem, size_t pos)
{
    if (!mem_ok(mem))
        return NULL;

    if (pos >= mem->__size)
        return NULL;

    return mem->__ptr + pos;
}

/* Return non-const pointer */
MEM_INLINE void* mem_mutable_ptr(mem_t* mem)
{
    if (!mem_ok(mem))
        return NULL;

    return mem->__ptr;
}

MEM_INLINE size_t mem_size(const mem_t* mem)
{
    if (!mem_ok(mem))
        return MEM_NPOS;

    return mem->__size;
}

MEM_INLINE size_t mem_cap(const mem_t* mem)
{
    if (!mem_ok(mem))
        return MEM_NPOS;

    return mem->__cap;
}

MEM_INLINE int mem_reserve(mem_t* mem, size_t cap)
{
    if (!mem_ok(mem))
        return -1;

    /* If capacity is insufficient */
    if (cap > mem->__cap)
    {
        unsigned char* ptr = NULL;
        size_t m;

        /* If not a dynamically allocated object */
        if (mem->__type != MEM_TYPE_DYNAMIC)
            return -1;

        /* Pick minimum capacity */
        if (cap < MEM_MIN_CAP)
            cap = MEM_MIN_CAP;

        /* Adjust capacity so the buffer is at least doubled */
        if ((m = mem->__cap * 2) > cap)
            cap = m;

        /* Expand allocation */
        ptr = (unsigned char*)realloc(mem->__ptr, cap);
        if (!ptr)
            return -1;

        mem->__ptr = ptr;
        mem->__cap = cap;
    }

    return 0;
}

MEM_INLINE int mem_resize(mem_t* mem, size_t size)
{
    if (!mem_ok(mem))
        return -1;

    if (mem_reserve(mem, size) != 0)
        return -1;

    if (size > mem->__size)
    {
        size_t rem = size - mem->__size;
        memset(mem->__ptr + mem->__size, 0, rem);
    }

    mem->__size = size;

    return 0;
}

MEM_INLINE int mem_clear(mem_t* mem)
{
    if (!mem_ok(mem))
        return -1;

    mem->__size = 0;
    return 0;
}

MEM_INLINE int mem_cpy(mem_t* mem, const void* ptr, size_t size)
{
    if (!mem_ok(mem))
        return -1;

    if (mem_reserve(mem, size) != 0)
        return -1;

    memcpy(mem->__ptr, ptr, size);
    mem->__size = size;

    return 0;
}

MEM_INLINE int mem_set(mem_t* mem, size_t pos, unsigned char c, size_t size)
{
    if (!mem_ok(mem))
        return -1;

    if (pos > mem->__size)
        return -1;

    if (pos + size > mem->__size)
        return -1;

    memset(mem->__ptr + pos, c, size);

    return 0;
}

MEM_INLINE int mem_insert(
    mem_t* mem,
    size_t pos,
    const void* ptr, /* If NULL, insert SIZE zero characters */
    size_t size)
{
    size_t rem;

    if (!mem_ok(mem))
        return -1;

    if (pos > mem->__size)
        return -1;

    if (mem_reserve(mem, mem->__size + size) != 0)
        return -1;

    rem = mem->__size - pos;

    if (rem)
        memmove(mem->__ptr + pos + size, mem->__ptr + pos, rem);

    if (ptr)
        memcpy(mem->__ptr + pos, ptr, size);
    else
        memset(mem->__ptr + pos, 0, size);

    mem->__size += size;

    return 0;
}

MEM_INLINE int mem_append(
    mem_t* mem,
    const void* ptr, /* If NULL, append SIZE zero characters */
    size_t size)
{
    if (!mem_ok(mem))
        return -1;

    if (mem_reserve(mem, mem->__size + size) != 0)
        return -1;

    if (ptr)
        memcpy(mem->__ptr + mem->__size, ptr, size);
    else
        memset(mem->__ptr + mem->__size, 0, size);

    mem->__size += size;

    return 0;
}

MEM_INLINE int mem_cat(
    mem_t* mem,
    const void* ptr, /* If NULL, append SIZE zero characters */
    size_t size)
{
    return mem_append(mem, ptr, size);
}

MEM_INLINE int mem_catc(mem_t* mem, unsigned char c)
{
    return mem_append(mem, &c, 1);
}

MEM_INLINE int mem_prepend(
    mem_t* mem,
    const void* ptr, /* If NULL, prepend SIZE zero characters */
    size_t size)
{
    return mem_insert(mem, 0, ptr, size);
}

MEM_INLINE int mem_remove(mem_t* mem, size_t pos, size_t size)
{
    size_t rem;

    if (!mem_ok(mem))
        return -1;

    if (pos > mem->__size)
        return -1;

    if (pos + size > mem->__size)
        return -1;

    rem = mem->__size - pos;

    if (rem)
        memmove(mem->__ptr + pos, mem->__ptr + pos + size, rem);

    mem->__size -= size;

    return 0;
}

#endif /* _MEM_H */
