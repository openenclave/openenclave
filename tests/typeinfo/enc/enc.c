// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/typeinfo.h>
#include <stdio.h>
#include <string.h>
#include "typeinfo_t.h"

/*
**==============================================================================
**
** Structure definitions:
**
**==============================================================================
*/

typedef struct _widget
{
    int value;
    const char* str;
} widget_t;

typedef struct _buffer
{
    uint8_t* data;
    size_t size;
} buffer_t;

typedef struct _gadget
{
    int value;
    widget_t* widgets;
    size_t num_widgets;
    buffer_t* buffer;
} gadget_t;

/*
**==============================================================================
**
** Hand-coded type information.
**
**==============================================================================
*/

// clang-format off

static oe_field_type_info_t _widget_ftis[] =
{
    OE_FTI_STRING(widget_t, str),
};

static oe_struct_type_info_t _widget_sti =
{
    sizeof(widget_t),
    _widget_ftis,
    OE_COUNTOF(_widget_ftis),
};

static oe_field_type_info_t _buffer_ftis[] =
{
    OE_FTI_ARRAY(buffer_t, data, sizeof(uint8_t), size)
};

static oe_struct_type_info_t _buffer_sti =
{
    sizeof(buffer_t),
    _buffer_ftis,
    OE_COUNTOF(_buffer_ftis),
};

static oe_field_type_info_t _gadget_ftis[] =
{
    OE_FTI_STRUCTS(gadget_t, widgets, widget_t, num_widgets, &_widget_sti),
    OE_FTI_STRUCT(gadget_t, buffer, buffer_t, &_buffer_sti),
};

static oe_struct_type_info_t _gadget_fti =
{
    sizeof(gadget_t),
    _gadget_ftis,
    OE_COUNTOF(_gadget_ftis),
};

// clang-format on

/*
**==============================================================================
**
** Define some structures.
**
**==============================================================================
*/

static widget_t _w[] = {
    {
        .value = 1,
        .str = "red",
    },
    {
        .value = 2,
        .str = "green",
    },
    {
        .value = 3,
        .str = "blue",
    },
};

static uint8_t _data[64] = {0x0A, 0x0B, 0x0C, 0x0D};

static buffer_t _buffer = {
    .data = _data,
    .size = sizeof(_data),
};

static gadget_t _g = {
    .value = 1000,
    .widgets = _w,
    .num_widgets = OE_COUNTOF(_w),
    .buffer = &_buffer,
};

/*
**==============================================================================
**
** test_typeinfo()
**
**==============================================================================
*/

int test_typeinfo(void)
{
    oe_struct_type_info_t* sti = &_gadget_fti;
    gadget_t* g;
    gadget_t* g2;
    size_t size = 0;

    /* Determine the size requirments for copying the gadget. */
    OE_TEST(oe_type_info_clone(sti, &_g, NULL, &size) == OE_BUFFER_TOO_SMALL);

    /* Initialize a flat allocator with stack space. */
    OE_TEST((g = calloc(1, size)));

    /* Initialize a flat allocator with stack space. */
    OE_TEST((g2 = calloc(1, size)));

    /* Peform a deep copy of the gadget. */
    {
        size_t tmp = size;
        OE_TEST(oe_type_info_clone(sti, &_g, g, &tmp) == OE_OK);
        OE_TEST(tmp == size);

        tmp = size;
        OE_TEST(oe_type_info_clone(sti, g, g2, &tmp) == OE_OK);
        OE_TEST(tmp == size);
    }

    OE_TEST(_g.value == g->value);
    OE_TEST(_g.value == g2->value);
    OE_TEST(_g.num_widgets == g->num_widgets);
    OE_TEST(_g.num_widgets == g2->num_widgets);
    OE_TEST(g->widgets);
    OE_TEST(g2->widgets);

    for (size_t i = 0; i < g->num_widgets; i++)
    {
        widget_t* w = &g->widgets[i];
        OE_TEST(w->str != NULL);

        switch (i)
        {
            case 0:
            {
                OE_TEST(w->value == 1);
                OE_TEST(strcmp(w->str, "red") == 0);
                break;
            }
            case 1:
            {
                OE_TEST(w->value == 2);
                OE_TEST(strcmp(w->str, "green") == 0);
                break;
            }
            case 2:
            {
                OE_TEST(w->value == 3);
                OE_TEST(strcmp(w->str, "blue") == 0);
                break;
            }
            default:
            {
                OE_TEST(false);
            }
        }
    }

    for (size_t i = 0; i < g2->num_widgets; i++)
    {
        widget_t* w = &g2->widgets[i];
        OE_TEST(w->str != NULL);

        switch (i)
        {
            case 0:
            {
                OE_TEST(w->value == 1);
                OE_TEST(strcmp(w->str, "red") == 0);
                break;
            }
            case 1:
            {
                OE_TEST(w->value == 2);
                OE_TEST(strcmp(w->str, "green") == 0);
                break;
            }
            case 2:
            {
                OE_TEST(w->value == 3);
                OE_TEST(strcmp(w->str, "blue") == 0);
                break;
            }
            default:
            {
                OE_TEST(false);
            }
        }
    }

    OE_TEST(g->buffer != NULL);
    OE_TEST(g->buffer->size == sizeof(_data));
    OE_TEST(memcmp(g->buffer->data, &_data, sizeof(_data)) == 0);

    OE_TEST(g2->buffer != NULL);
    OE_TEST(g2->buffer->size == sizeof(_data));
    OE_TEST(memcmp(g2->buffer->data, &_data, sizeof(_data)) == 0);

    OE_TEST(g2->widgets != NULL);

    /* Test update. */
    {
        static const uint8_t _buf[] = {0, 2, 3, 4, 5, 6, 7, 8, 9};
        memcpy(g->buffer->data, _buf, OE_COUNTOF(_buf));
        g->buffer->size = OE_COUNTOF(_buf);

        /* Update g2 from g. */
        OE_TEST(oe_type_info_update(&_gadget_fti, g, g2) == OE_OK);

        OE_TEST(g2->buffer != NULL);
        OE_TEST(g2->buffer->data != NULL);
        OE_TEST(g2->buffer->size == OE_COUNTOF(_buf));
        OE_TEST(memcmp(g2->buffer->data, &_buf, sizeof(_buf)) == 0);
    }

    free(g);
    free(g2);

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
