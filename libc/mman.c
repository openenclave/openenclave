// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include <stdlib.h>

#include "mman.h"
#include "openenclave/bits/defs.h"
#include "openenclave/bits/result.h"
#include "syscall.h"

static oe_mapping_t* _mappings;
static oe_spinlock_t _lock;

static void _clear_mappings(void)
{
    oe_mapping_t* m = _mappings;
    _mappings = 0;
    while (m)
    {
        oe_mapping_t* next = m->next;
        free((void*)m->start);
        m->start = 0;
        free(m->status_vector);
        m->status_vector = NULL;
        free(m);
        m = next;
    }
}

static void _call_atexit(void)
{
    atexit(_clear_mappings);
}

static void _register_atexit_callback(void)
{
    static oe_once_t once = OE_ONCE_INITIALIZER;
    oe_once(&once, _call_atexit);
}

static oe_result_t _validate_mmap_parameters(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    oe_result_t result = OE_UNEXPECTED;
    int flags_copy = flags;

    // If addr is not NULL, then the kernel takes it as a hint about where to
    // place the mapping; on Linux, the kernel will pick a nearby page boundary
    // (but always above or equal to the value specified by
    // /proc/sys/vm/mmap_min_addr) and attempt to create the mapping there.
    // OE currently does not support this usage.
    if (addr != NULL)
    {
        // Previously, an error was raised in this case. To support more
        // use cases, the addr hint is ignored instead.
    }

    // PROT_NONE and PROT_EXEC are not supported.
    if (prot == PROT_NONE || (prot & PROT_EXEC))
        OE_RAISE_MSG(OE_UNSUPPORTED, "unsupported `prot` value %d", prot);

    if (length == 0)
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "length must be non zero");

    enum
    {
        UNSUPPORTED,
        IGNORED,
        SUPPORTED
    };
    static struct support
    {
        int flag;
        int support;
    } flags_table[] = {
        {MAP_SHARED, SUPPORTED},
        {MAP_SHARED_VALIDATE, SUPPORTED},
        {MAP_PRIVATE, SUPPORTED},
#ifdef MAP_32BIT
        {MAP_32BIT, UNSUPPORTED},
#endif
        {MAP_ANON, SUPPORTED},
        {MAP_ANONYMOUS, SUPPORTED},
        {MAP_DENYWRITE, IGNORED /* by spec */},
        {MAP_EXECUTABLE, IGNORED /* by spec */},
        {MAP_FILE, IGNORED /* by spec */},
        {MAP_FIXED, UNSUPPORTED},
        {MAP_FIXED_NOREPLACE, UNSUPPORTED},
        {MAP_GROWSDOWN, UNSUPPORTED},
        {MAP_HUGETLB, UNSUPPORTED},
        {MAP_HUGE_2MB, UNSUPPORTED},
        {MAP_HUGE_1GB, UNSUPPORTED},
        {MAP_LOCKED, UNSUPPORTED},
        {MAP_NONBLOCK, IGNORED /* no special handling by OE */},
        {MAP_NORESERVE, IGNORED /* no special handling by OE */},
        {MAP_POPULATE, IGNORED /* no special handling by OE */},
        {MAP_STACK, IGNORED /* currently no-op on Linux */},
        {MAP_SYNC, IGNORED /* no special handling needed for OE */},
        // MUSL doesn't defined MAP_UNINITIALIZED
        // { MAP_UNINITIALIZED, SUPPORTED }
    };

    // Of the above flags, only MAP_FIXED is specified in POSIX.1-2001 and
    // POSIX.1-2008.  However, most systems also support MAP_ANONYMOUS.

    for (int i = 0; i < OE_COUNTOF(flags_table); ++i)
    {
        if (flags_copy & flags_table[i].flag)
        {
            if (flags_table[i].support == UNSUPPORTED)
                OE_RAISE_MSG(
                    OE_UNSUPPORTED,
                    "unsupported `flag` value %d",
                    flags_table[i].flag);

            // Remove flag.
            flags_copy &= ~flags_table[i].flag;
        }
    }

    if (flags_copy)
        OE_RAISE_MSG(OE_INVALID_PARAMETER, "invalid flag supplied");

    // MAP_SHARED, MAP_SHARED_VALIDATE, MAP_PRIVATE are all treated the same
    // since an enclave is a single process. Exactly one of them must be
    // specified. They occupy the lower two bits of flags.
    OE_STATIC_ASSERT(MAP_SHARED == 0x01);
    OE_STATIC_ASSERT(MAP_PRIVATE == 0x02);
    OE_STATIC_ASSERT(MAP_SHARED_VALIDATE == 0x03);

    if (!(flags & 0x03))
        OE_RAISE_MSG(
            OE_INVALID_PARAMETER,
            "`flags` must specify exactly one of MAP_SHARED or "
            "MAP_SHARED_VALIDATE or MAP_PRIVATE");

    if (flags & MAP_ANON || flags & MAP_ANONYMOUS)
    {
        // The fd argument is ignored; however, some implementations require fd
        // to be -1 if MAP_ANONYMOUS (or MAP_ANON) is specified. The offset
        // argument should be zero.
        if (offset != 0)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "offset` must be zero for anonymous mapping.");
    }

    result = OE_OK;
done:
    if (result != OE_OK)
        oe_errno = OE_EINVAL;

    return result;
}

// See https://www.man7.org/linux/man-pages/man2/mmap.2.html for
// semantics of mmap and munmap.
void* oe_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    oe_result_t result = OE_UNEXPECTED;
    void* ptr = NULL;
    void* vector = NULL;
    oe_mapping_t* m = NULL;
    size_t vector_length = 0;
    int ret = 0;

    OE_CHECK(_validate_mmap_parameters(addr, length, prot, flags, fd, offset));

    _register_atexit_callback();

    // length is rounded up to nearest page size.
    OE_CHECK(oe_safe_round_up_u64(length, OE_PAGE_SIZE, &length));
    OE_CHECK(oe_safe_round_up_u64(length / 8, 8, &vector_length));

    // Allocate objects.
    vector = (uint8_t*)calloc(vector_length, 1);
    m = (oe_mapping_t*)malloc(sizeof(*m));
    if (!vector || !m)
    {
        oe_errno = OE_ENOMEM;
        OE_RAISE(OE_OUT_OF_MEMORY);
    }

    if (((ret = posix_memalign(&ptr, OE_PAGE_SIZE, length)) != 0) || !ptr)
    {
        // posix_memalign does not set errno (by spec).
        // Set it ourselves.
        oe_errno = ret;
        OE_RAISE_MSG(
            OE_OUT_OF_MEMORY, "posix_memalign failed with code %d", ret);
    }

    // Set up mapping.
    m->start = (uint64_t)ptr;
    OE_CHECK(oe_safe_add_u64((uint64_t)m->start, length, (uint64_t*)&m->end));
    m->status_vector = vector;
    memset(ptr, 0, length);

    // Set relevant bits of status vector to 1.
    {
        int bv_idx = 0;
        uint8_t bit_mask = 0x01;
        // Since m->end has been rounded to OE_PAGE_SIZE and been validated via
        // oe_safe_add_u64, it is safe to add OE_PAGE_SIZE to `a` since it won't
        // overflow.
        for (uint64_t a = m->start; a < m->end; a += OE_PAGE_SIZE)
        {
            m->status_vector[bv_idx] |= bit_mask;
            bit_mask <<= 1;
            if (!bit_mask)
            {
                // Move to next byte in status vector.
                ++bv_idx;
                bit_mask = 0x01;
            }
        }
    }

    // Update mappings list.
    oe_spin_lock(&_lock);
    m->next = _mappings;
    _mappings = m;
    oe_spin_unlock(&_lock);

    result = OE_OK;

done:
    if (result != OE_OK)
    {
        free(vector);
        free(ptr);
        free(m);
        return MAP_FAILED;
    }
    return ptr;
}

static void _munmap(
    oe_mapping_t* prev,
    oe_mapping_t* m,
    uint64_t start,
    uint64_t end)
{
    while (m)
    {
        if (end <= m->start || start >= m->end)
        {
            // Specified address range does not intersect with current mapping.
            prev = m;
            m = m->next;
            continue;
        }

        // Specified address range intersects with current mapping.

        // Unmap part of address range that lies to the left of current mapping.
        if (start < m->start)
            _munmap(m, m->next, start, m->start);

        // Unmap part of address range that lies to the right of current
        // mapping.
        if (end > m->end)
            _munmap(m, m->next, m->end, end);

        bool delete = true;
        if (start > m->start || end < m->end)
        {
            // Partial unmapping.
            uint8_t bit_mask = 1;
            int bv_idx = 0;

            // Mark all pages in given address range as unmapped.
            for (uint64_t a = m->start; a < m->end; a += OE_PAGE_SIZE)
            {
                // If pages lies in the specified range, unset its status.
                if (start <= a && a < end)
                    m->status_vector[bv_idx] &= ~bit_mask;

                bit_mask <<= 1;
                if (!bit_mask)
                {
                    // Retain the mapping if any bit in the vector is set.
                    delete = delete &&!m->status_vector[bv_idx];
                    bit_mask = 1;
                    bv_idx++;
                }
            }
            delete = delete &&!m->status_vector[bv_idx];
        }

        if (delete)
        {
            if (prev)
                prev->next = m->next;
            else
                _mappings = m->next;
            free(m->status_vector);
            free((void*)m->start);
            free(m);
        }

        break;
    }
}

int oe_munmap(void* addr, uint64_t length)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t start = (uint64_t)addr;
    uint64_t end = 0;
    OE_CHECK(oe_safe_add_u64(start, length, &end));
    OE_CHECK(oe_safe_round_up_u64(end, OE_PAGE_SIZE, &end));

    if ((start % OE_PAGE_SIZE) != 0)
    {
        oe_errno = OE_EINVAL;
        goto done;
    }

    oe_spin_lock(&_lock);
    _munmap(NULL, _mappings, start, end);
    oe_spin_unlock(&_lock);
    oe_errno = 0;
    result = OE_OK;
done:
    return (result == OE_OK) ? 0 : -1;
}

void* mmap(void* start, size_t len, int prot, int flags, int fd, off_t off)
{
    return (void*)__syscall(SYS_mmap, start, len, prot, flags, fd, off);
}

int munmap(void* start, size_t len)
{
    return (int)syscall(SYS_munmap, start, len);
}

// Needed for MUSL
OE_WEAK_ALIAS(mmap, __mmap);
OE_WEAK_ALIAS(mmap, mmap64);
OE_WEAK_ALIAS(munmap, __munmap);

// Utility function for tests.
oe_mapping_t* oe_test_get_mappings(void)
{
    return _mappings;
}
