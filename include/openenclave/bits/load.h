#ifndef _OE_LOAD_H
#define _OE_LOAD_H

#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

#define OE_MAX_SEGMENTS 16

#define OE_SEGMENT_FLAG_READ   1
#define OE_SEGMENT_FLAG_WRITE  2
#define OE_SEGMENT_FLAG_EXEC   4

typedef struct _OE_Segment
{
    /* Pointer to segment from ELF file */
    void* filedata; 

    /* Size of this segment in the ELF file */
    oe_size_t filesz; 

    /* Size of this segment in memory */
    oe_size_t memsz; 

    /* Offset of this segment within file */
    oe_uint64_t offset; 

    /* Virtual address of this segment */
    oe_uint64_t vaddr; 

    /* Memory protection flags for this segment */
    oe_uint32_t flags;
}
OE_Segment;

OE_INLINE oe_uint64_t __OE_RoundUpToPageSize(oe_uint64_t x)
{
    oe_uint64_t n = OE_PAGE_SIZE;
    return (x + n - 1) / n * n;
}

OE_INLINE oe_uint64_t __OE_RoundDownToPageSize(oe_uint64_t x)
{
    return x & ~(OE_PAGE_SIZE - 1);
}

OE_Result __OE_LoadSegments(
    const char* path,
    OE_Segment segments[OE_MAX_SEGMENTS],
    oe_size_t* nsegments,
    oe_uint64_t* entryaddr, /* virtual address of entry point */
    oe_uint64_t* textaddr); /* virtual address of text section */

OE_Result __OE_CalculateSegmentsSize(
    const OE_Segment* segments,
    oe_size_t nsegments,
    oe_size_t* size);

OE_Result __OE_CombineSegments(
    const OE_Segment* segments,
    oe_size_t nsegments,
    OE_Page** pages,
    oe_size_t* npages);

OE_EXTERNC_END

#endif /* _OE_LOAD_H */
