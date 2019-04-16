// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_LIST_H
#define _OE_INTERNAL_LIST_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_list_node oe_list_node_t;

typedef struct _oe_list oe_list_t;

struct _oe_list
{
    oe_list_node_t* head;
    oe_list_node_t* tail;
    size_t size;
};

struct _oe_list_node
{
    oe_list_node_t* prev;
    oe_list_node_t* next;
};

OE_INLINE void oe_list_remove(oe_list_t* list, oe_list_node_t* node)
{
    if (node->prev)
        node->prev->next = node->next;
    else
        list->head = node->next;

    if (node->next)
        node->next->prev = node->prev;
    else
        list->tail = node->prev;

    list->size--;
}

OE_INLINE void oe_list_prepend(oe_list_t* list, oe_list_node_t* node)
{
    if (list->head)
    {
        node->prev = NULL;
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

OE_INLINE void oe_list_append(oe_list_t* list, oe_list_node_t* node)
{
    if (list->tail)
    {
        node->next = NULL;
        node->prev = list->tail;
        list->tail->next = node;
        list->tail = node;
    }
    else
    {
        node->next = NULL;
        node->prev = NULL;
        list->head = node;
        list->tail = node;
    }

    list->size++;
}

typedef void (*oe_list_free_func)(void* ptr);

OE_INLINE void oe_list_free(oe_list_t* list, oe_list_free_func func)
{
    if (func)
    {
        for (oe_list_node_t* p = list->head; p;)
        {
            oe_list_node_t* next = p->next;
            (*func)(p);
            p = next;
        }

        list->head = NULL;
        list->tail = NULL;
        list->size = 0;
    }
}

OE_EXTERNC_END

#endif /* _OE_INTERNAL_LIST_H */
