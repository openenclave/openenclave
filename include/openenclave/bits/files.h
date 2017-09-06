#ifndef _OE_FILES_H
#define _OE_FILES_H

#include <stdio.h>
#include <openenclave/defs.h>
#include <openenclave/result.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

oe_bool __OE_FileExists(
    const char* path);

OE_Result __OE_LoadFile(
    const char* path,
    oe_size_t extraBytes,
    void** data,
    oe_size_t* size);

OE_Result __OE_LoadPages(
    const char* path,
    OE_Page** pages,
    oe_size_t* npages);

OE_EXTERNC_END

#endif /* _OE_FILES_H */
