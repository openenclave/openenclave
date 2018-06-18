// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _VOPRINTF_H
#define _VOPRINTF_H

typedef struct _oe_out oe_out_t;

struct _oe_out
{
    ssize_t (*write)(oe_out_t* out, const void* buf, size_t count);
};

int oe_voprintf(oe_out_t* out, const char* fmt, oe_va_list ap);

#endif /* _VOPRINTF_H */
