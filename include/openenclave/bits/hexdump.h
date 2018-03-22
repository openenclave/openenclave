// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HEXDUMP_H
#define _OE_HEXDUMP_H

#include <openenclave/defs.h>
#include <openenclave/types.h>

OE_EXTERNC_BEGIN

void OE_HexDump(const void* data, size_t size);

OE_EXTERNC_END

#endif /* _OE_HEXDUMP_H */
