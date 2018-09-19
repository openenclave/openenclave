// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/typeinfo.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tester_t.h"

static struct Object* _MakeObject(const char* name, size_t id)
{
    struct Object* p;

    if (!(p = (struct Object*)calloc(1, sizeof(struct Object))))
        return NULL;

    if (!(p->name = strdup(name)))
    {
        free(p);
        return NULL;
    }

    p->id = id;

    return p;
}

OE_EXTERNC uint32_t ReturnUint32()
{
    return 32;
}

OE_EXTERNC char* ReturnStr()
{
    return strdup("str");
}

OE_EXTERNC struct Date ReturnDate()
{
    struct Date d;
    d.mm = 12;
    d.dd = 30;
    d.yyyy = 2017;
    return d;
}

OE_EXTERNC struct Object ReturnObject()
{
    struct Object o;
    o.id = 6;
    o.name = strdup("Object");
    return o;
}

OE_EXTERNC struct Node* ReturnLinkedList()
{
    struct Node* p;
    struct Node* q;
    struct Node* r;

    if (!(p = (struct Node*)calloc(1, sizeof(struct Node))))
        return NULL;

    if (!(q = (struct Node*)calloc(1, sizeof(struct Node))))
    {
        free(p);
        return NULL;
    }

    if (!(r = (struct Node*)calloc(1, sizeof(struct Node))))
    {
        free(p);
        free(q);
        return NULL;
    }

    p->next = q;
    p->value = 1;

    q->value = 2;
    q->next = r;

    r->value = 3;
    r->next = NULL;

    return p;
}

OE_EXTERNC struct Object* ReturnObjects(size_t count)
{
    struct Object* p;
    size_t i;

    if (!(p = (struct Object*)calloc(count, sizeof(Object))))
        return NULL;

    for (i = 0; i < count; i++)
    {
        char buf[64];
        snprintf(buf, sizeof(buf), "Object%zu", i);
        p[i].id = i;
        p[i].name = strdup(buf);
    }

    return p;
}

OE_EXTERNC char* TestStrdup(const char* s)
{
    return strdup(s);
}

OE_EXTERNC int CopyObject(struct Object* dest, const struct Object* src)
{
    oe_result_t r;

    if (!dest || !src)
        return -1;

    r = oe_destroy_struct(&Object_ti, dest, free);
    if (r != OE_OK)
        return -1;

    memset(dest, 0, sizeof(Object));

    r = oe_copy_struct(&Object_ti, src, dest, malloc);
    if (r != OE_OK)
        return -1;

    return 0;
}

OE_EXTERNC int32_t
CopyObjects(struct Object dest[2], const struct Object src[2])
{
    if (CopyObject(&dest[0], &src[0]) != 0)
        return -1;

    if (CopyObject(&dest[1], &src[1]) != 0)
        return -1;

#if 0
    /* Intentional buffer overrun */
    if (CopyObject(&dest[2], &src[1]) != 0)
        return -1;
#endif

    return 0;
}

OE_EXTERNC int32_t ECALL_MultipleParams(
    const char* strIn,
    uint32_t numIn,
    const struct Object* objectIn,
    char* strOut,
    uint32_t* numOut,
    struct Object* objectOut,
    struct Object** objectRefOut)
{
    if (!strIn || !objectIn || !strOut || !objectOut)
        return -1;

    /* str */
    strncpy(strOut, strIn, strlen(strIn));

    /* num */
    *numOut = numIn;

    /* object */
    if (CopyObject(objectOut, objectIn) != 0)
        return -1;

#if 0
    oe_print_struct(&Object_ti, objectIn);
#endif

    if (objectRefOut)
    {
#if 0
        if (*objectRefOut)
            oe_print_struct(&Object_ti, *objectRefOut);
#endif
        *objectRefOut = _MakeObject("O10", 10);
    }

    return 0;
}

OE_EXTERNC int32_t GetObjectRef(struct Object** object)
{
    if (!object)
        return -1;

    *object = _MakeObject("GetObjectRef", 12);
    return 0;
}

OE_EXTERNC int32_t ModifyObject(struct Object* object)
{
    if (!object)
        return -1;

    object->id++;
    return 0;
}

static size_t _Strlcpy(char* dest, const char* src, size_t size)
{
    const char* start = src;

    if (size)
    {
        char* end = dest + size - 1;

        while (*src && dest != end)
            *dest++ = (char)*src++;

        *dest = '\0';
    }

    while (*src)
        src++;

    return src - start;
}

OE_EXTERNC size_t TestStrlcpy(char* dest, const char* src, size_t dsize)
{
    if (!dest || !src)
        return 0;

    return _Strlcpy(dest, src, dsize);
}

OE_EXTERNC size_t TestOptQualifier(char* p1, const char* p2, size_t p1size)
{
    return 0;
}

OE_EXTERNC void ReturnVoid()
{
}

OE_EXTERNC int* ReturnIntPtr(int* p, size_t n)
{
    if (!p)
        return NULL;

#if 0
    oe_printf("ReturnIntPtr(p=%p, n=%zu)\n", p, n);

    for (size_t i = 0; i < n; i++)
        oe_printf("ELEM{%d}\n", p[i]);
#endif

    int* ret = (int*)malloc(n * sizeof(int));
    memcpy(ret, p, n * sizeof(int));
    return ret;
}

OE_EXTERNC void TestCallback(void* func)
{
    typedef void (*Func)(const char* str);
    Func f = (Func)func;

    if (f)
        f("TestCallback");
}

OE_EXTERNC bool TestIntPtrRef(int** intPtrOut, size_t n)
{
    if (!intPtrOut)
        return false;

    if (!(*intPtrOut = (int*)malloc(n * sizeof(int))))
        return false;

    for (size_t i = 0; i < n; i++)
        (*intPtrOut)[i] = i;

    return true;
}

OE_EXTERNC void TestBufferOverrun(char str[8])
{
    /* Intentional buffer overrun (will be detected by ENC) */
    strlcpy(str, "123456789", 9);
}

OE_EXTERNC void* ReturnEnclaveMemory()
{
    static uint8_t _memory[1024];
    return _memory;
}

OE_EXTERNC void TestBufferCopy(
    void* dest,
    const void* src,
    size_t n,
    bool forceOverwrite)
{
    if (forceOverwrite)
        memcpy(dest, src, n + 1);
    else
        memcpy(dest, src, n);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */
