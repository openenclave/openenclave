// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_HOSTBATCH_H
#define _OE_HOSTBATCH_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_host_batch oe_host_batch_t;

oe_host_batch_t* oe_host_batch_new(size_t capacity);

void oe_host_batch_delete(oe_host_batch_t* batch);

void* oe_host_batch_malloc(oe_host_batch_t* batch, size_t size);

void* oe_host_batch_calloc(oe_host_batch_t* batch, size_t size);

char* oe_host_batch_strdup(oe_host_batch_t* batch, const char* str);

int oe_host_batch_free(oe_host_batch_t* batch);

OE_EXTERNC_END

#endif /* _OE_HOSTBATCH_H */
