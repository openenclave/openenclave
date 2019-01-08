/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#pragma once

typedef struct _oe_exception_handler_entry {
    struct _oe_exception_handler_entry* next;
    struct _oe_exception_handler_entry* prev;
    oe_vectored_exception_handler_t handler;
} oe_exception_handler_entry;

extern oe_exception_handler_entry g_OEExceptionHandlerHead;

void* oe_register_exception_handler(void);
int oe_unregister_exception_handler(void* handle);
