// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/typeinfo.h>
#include <openenclave/host.h>
#include <cwchar>
#include "CXXObject.h"
#include "typeinfo_u.h"

#define err(...) OE_PutErr(__VA_ARGS__)

static void __Test(const char* file, unsigned int line, const char* cond)
{
    fprintf(stderr, "%s(%u): %s: (test failed)\n", file, line, cond);
}

#define TEST(COND)                             \
    do                                         \
    {                                          \
        if (!(COND))                           \
        {                                      \
            __Test(__FILE__, __LINE__, #COND); \
            exit(1);                           \
        }                                      \
    } while (0)

OE_EXTERNC int32_t
UCopy(char* p, size_t m, const char* q, size_t n, struct Object** object)
{
    return 0;
}

int InitObject(struct Object& object, size_t id, const char* name)
{
    memset(&object, 0, sizeof(Object));
    object.id = id;

    if (!(object.name = strdup(name)))
        return -1;

    return 0;
}

void DestroyObject(struct Object& object)
{
}

struct Object* MakeObject(size_t id, const char* name)
{
    struct Object* p;

    if (!(p = (struct Object*)malloc(sizeof(struct Object))))
        return NULL;

    p->id = id;

    if (!(p->name = strdup(name)))
    {
        free(p);
        return NULL;
    }

    return p;
}

int TestContainer(bool trace)
{
    Object o;
    memset(&o, 0, sizeof(o));
    o.id = sizeof(o);
    o.name = (char*)"Object";

    Container c;
    memset(&c, 0, sizeof(c));

    uint32_t arr[] = {100, 200, 300};
    c.arrData = arr;
    c.arrSize = OE_COUNTOF(arr);

    if (trace)
        OE_PrintStruct(&Container_ti, &c);

    c.object = &o;
    c.size = 1;
    c.b = true;

    c.e.xxx = 1234;
    c.e.yyy = 5678;
    strcpy(c.e.str, "My char array");
    strcpy(c.e.cstr, "ABCDEFG\r\n\177");
    wcscpy(c.e.wstr, L"ABCDEFG\r\n\177");

    Object objects[2];
    objects[0].id = sizeof(Object);
    objects[0].name = (char*)("Object1");
    objects[1].id = sizeof(Object);
    objects[1].name = (char*)("Object1");
    c.e.objects = objects;
    c.e.nobjects = 2;

    memcpy(&c.ae[1], &c.e, sizeof(c.e));

    unsigned char varr[5] = {0, 1, 2, 3, 4};
    c.varr = varr;
    c.sizevarr = 5;

    if (trace)
        OE_PrintStruct(&Container_ti, &c);

    Container* s;
    OE_Result result = OE_CloneStruct(&Container_ti, &c, (void**)&s, malloc);

    if (result != OE_OK)
    {
        fprintf(stderr, "error: OE_CloneStruct(): %u\n", result);
        exit(1);
    }

    if (trace)
        OE_PrintStruct(&Container_ti, s);

#if 0
    if ((result = OE_ImportStruct(&Container_ti, s)) != OE_OK)
    {
        fprintf(stderr, "error: OE_ImportStruct(): %u\n", result);
        exit(1);
    }
#endif

    OE_FreeStruct(&Container_ti, s, free);

    return 0;
}

static int TestObject(bool trace)
{
    OE_Result result;
    Object* object = MakeObject(sizeof(Object), "Object");

    if (!object)
        err("MakeObject");

    TEST(!OE_PadStruct(&Object_ti, object));
    TEST(!OE_TestStructPadding(&Object_ti, object));

    if (trace)
        OE_PrintStruct(&Object_ti, object);

    if ((result = OE_FreeStruct(&Object_ti, object, free)))
        err("OE_FreeStruct");

    printf("=== passed TestObject()\n");
    return 0;
}

int TestCopyOver(bool trace)
{
    Object* obj1;
    Object* obj2;

    if (!(obj1 = MakeObject(10, "O10")))
        return -1;

    if (!(obj2 = MakeObject(20, "O20")))
        return -1;

    if (OE_FreeStruct(&Object_ti, obj1, free) != OE_OK)
        return -1;

    if (OE_FreeStruct(&Object_ti, obj2, free) != OE_OK)
        return -1;

    printf("=== passed TestCopyOver()\n");
    return 0;
}

int TestAllTypes(bool trace)
{
    const OE_StructTI* sti = &AllTypes_ti;
    AllTypes x;
    AllTypes y;
    memset(&x, 0, sizeof(x));
    memset(&y, 0, sizeof(y));

    x.s8 = -8;
    x.u8 = 8;
    x.s16 = -16;
    x.u16 = 16;
    x.s32 = -32;
    x.u32 = 32;
    x.s64 = -64;
    x.u64 = 64;
    x.r32 = 32.0;
    x.r64 = 64.0;
    x.by = 0xBB;
    x.b = true;
    x.c = 'C';
    x.w = 'W';
    x.s = 99;
    x.ss = -99;
    x.str = strdup("str");
    x.strn = 4;
    x.wcs = wcsdup(L"wcs");
    strcpy(x.stra, "stra");
    wcscpy(x.wcsa, L"wcsa");
    x.obj1.id = 1;
    x.obj1.name = strdup("Object1");
    x.obj2 = MakeObject(2, "Object2");
    uint32_t* data = (uint32_t*)malloc(sizeof(uint32_t) * 3);
    data[0] = 0;
    data[1] = 1;
    data[2] = 2;
    x.data = data;
    x.size = 3;

    if (trace)
        OE_PrintStruct(&AllTypes_ti, &x);

    if (OE_CopyStruct(&AllTypes_ti, &x, &y, malloc) != OE_OK)
        OE_PutErr("OE_CopyStruct()");

    bool flag;
    if (OE_StructEq(&AllTypes_ti, &x, &y, &flag) != OE_OK || !flag)
        err("OE_StructEq()");

    if (trace)
        OE_PrintStruct(&AllTypes_ti, &y);

#if 0
    OE_PrintStruct(&AllTypes_ti, &x);
    OE_PrintStruct(&AllTypes_ti, &x);
#endif

    // Test OE_ClearArg():
    {
        AllTypes z;

        if (OE_CopyStruct(sti, &y, &z, malloc) != OE_OK)
            OE_PutErr("OE_CopyStruct()");

        TEST(!OE_ClearArgByName(sti, &y, "stra", 0, z.stra, free));
        TEST(strcmp(z.stra, "") == 0);
        TEST(!OE_ClearArgByName(sti, &y, "str", 0, z.str, free));
        TEST(strcmp(z.str, "") == 0);

        TEST(!OE_ClearArgByName(sti, &y, "str", 1, &z.str, free));
        TEST(z.str == NULL);
        TEST(!OE_ClearArgByName(sti, &y, "wcs", 1, &z.wcs, free));
        TEST(z.wcs == NULL);
        TEST(!OE_ClearArgByName(sti, &y, "wcsa", 0, z.wcsa, free));
        TEST(wcscmp(z.wcsa, L"") == 0);
        TEST(!OE_ClearArgByName(sti, &y, "s8", 0, &z.s8, free));
        TEST(!OE_ClearArgByName(sti, &y, "u8", 0, &z.u8, free));
        TEST(!OE_ClearArgByName(sti, &y, "s16", 0, &z.s16, free));
        TEST(!OE_ClearArgByName(sti, &y, "u16", 0, &z.u16, free));
        TEST(!OE_ClearArgByName(sti, &y, "s32", 0, &z.s32, free));
        TEST(!OE_ClearArgByName(sti, &y, "u32", 0, &z.u32, free));
        TEST(!OE_ClearArgByName(sti, &y, "s64", 0, &z.s64, free));
        TEST(!OE_ClearArgByName(sti, &y, "u64", 0, &z.u64, free));
        TEST(!OE_ClearArgByName(sti, &y, "r32", 0, &z.r32, free));
        TEST(!OE_ClearArgByName(sti, &y, "r64", 0, &z.r64, free));
        TEST(!OE_ClearArgByName(sti, &y, "by", 0, &z.by, free));
        TEST(!OE_ClearArgByName(sti, &y, "b", 0, &z.b, free));
        TEST(!OE_ClearArgByName(sti, &y, "c", 0, &z.c, free));
        TEST(!OE_ClearArgByName(sti, &y, "w", 0, &z.w, free));
        TEST(!OE_ClearArgByName(sti, &y, "s", 0, &z.s, free));
        TEST(!OE_ClearArgByName(sti, &y, "ss", 0, &z.ss, free));
        TEST(!OE_ClearArgByName(sti, &y, "strn", 0, &z.strn, free));
        TEST(!OE_ClearArgByName(sti, &y, "obj1", 0, &z.obj1, free));
        TEST(!OE_ClearArgByName(sti, &y, "obj2", 1, &z.obj2, free));
        TEST(!OE_ClearArgByName(sti, &y, "data", 1, &z.data, free));
        TEST(!OE_ClearArgByName(sti, &y, "size", 0, &z.size, free));

        AllTypes n;
        memset(&n, 0, sizeof(n));

        bool flag;
        TEST(!OE_StructEq(&AllTypes_ti, &z, &n, &flag));
        TEST(flag);
    }

    // Test OE_SetArg():
    {
        AllTypes z;
        memset(&z, 0, sizeof(z));

        TEST(!OE_SetArgByName(sti, &y, "s8", 0, &z.s8, malloc));
        TEST(!OE_SetArgByName(sti, &y, "u8", 0, &z.u8, malloc));
        TEST(!OE_SetArgByName(sti, &y, "s16", 0, &z.s16, malloc));
        TEST(!OE_SetArgByName(sti, &y, "u16", 0, &z.u16, malloc));
        TEST(!OE_SetArgByName(sti, &y, "s32", 0, &z.s32, malloc));
        TEST(!OE_SetArgByName(sti, &y, "u32", 0, &z.u32, malloc));
        TEST(!OE_SetArgByName(sti, &y, "s64", 0, &z.s64, malloc));
        TEST(!OE_SetArgByName(sti, &y, "u64", 0, &z.u64, malloc));
        TEST(!OE_SetArgByName(sti, &y, "r32", 0, &z.r32, malloc));
        TEST(!OE_SetArgByName(sti, &y, "r64", 0, &z.r64, malloc));
        TEST(!OE_SetArgByName(sti, &y, "by", 0, &z.by, malloc));
        TEST(!OE_SetArgByName(sti, &y, "b", 0, &z.b, malloc));
        TEST(!OE_SetArgByName(sti, &y, "c", 0, &z.c, malloc));
        TEST(!OE_SetArgByName(sti, &y, "w", 0, &z.w, malloc));
        TEST(!OE_SetArgByName(sti, &y, "s", 0, &z.s, malloc));
        TEST(!OE_SetArgByName(sti, &y, "ss", 0, &z.ss, malloc));
        TEST(!OE_SetArgByName(sti, &y, "str", 1, &z.str, malloc));
        TEST(!OE_SetArgByName(sti, &y, "strn", 0, &z.strn, malloc));
        TEST(!OE_SetArgByName(sti, &y, "wcs", 1, &z.wcs, malloc));
        TEST(!OE_SetArgByName(sti, &y, "stra", 0, z.stra, malloc));
        TEST(!OE_SetArgByName(sti, &y, "wcsa", 0, z.wcsa, malloc));
        TEST(!OE_SetArgByName(sti, &y, "obj1", 0, &z.obj1, malloc));
        TEST(!OE_SetArgByName(sti, &y, "obj2", 1, &z.obj2, malloc));
        TEST(!OE_SetArgByName(sti, &y, "data", 1, &z.data, malloc));
        TEST(!OE_SetArgByName(sti, &y, "size", 0, &z.size, malloc));

        bool flag;
        TEST(!OE_StructEq(&AllTypes_ti, &z, &y, &flag));
        TEST(flag);

        OE_DestroyStruct(&AllTypes_ti, &z, free);
    }

    OE_DestroyStruct(&AllTypes_ti, &x, free);
    OE_DestroyStruct(&AllTypes_ti, &y, free);

    printf("=== passed TestAllTypes()\n");
    return 0;
}

int MyFunctionCall(MyFunctionArgs* a)
{
    TEST(a->str);
    TEST(a->nstr);

    strncpy(a->str, "aaaaaaaaaaaaaaaaaaaaaa", a->nstr - 1);

    if (a->u32)
        *a->u32 = 66;

    a->u32a[0] = 10;
    a->u32a[1] = 20;
    a->u32a[2] = 30;
    a->u32a[3] = 40;

    *a->stra = '\0';
    strncat(a->stra, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 31);

    a->objp->id = 11111111;
    a->objr->id = 22222222;

    return 0;
}

int MyFunction(
    const char* cstr,
    char* str,
    uint32_t nstr,
    uint32_t* u32,
    uint32_t u32a[4],
    char stra[3],
    struct Object obj,
    struct Object* objp,
    struct Object** objr)
{
    const OE_StructTI* ti = &MyFunctionArgs_ti;
    struct MyFunctionArgs args;
    memset(&args, 0, sizeof(args));
    args.cstr = cstr;
    args.str = str;
    args.nstr = nstr;
    args.u32 = u32;
    memcpy(args.u32a, u32a, sizeof(args.u32a));
    memcpy(args.stra, stra, sizeof(args.stra));
    args.obj = obj;
    args.objp = objp;
    if (objr)
        args.objr = *objr;
    struct MyFunctionArgs* a;

    if (OE_CloneStruct(ti, &args, (void**)&a, malloc) != OE_OK)
        return -1;

    bool flag = false;
    if (OE_StructEq(ti, &args, a, &flag) != OE_OK || !flag)
        OE_PutErr("OE_StructEq");

    if (MyFunctionCall(a) != 0)
        OE_PutErr("MyFunctionCall()");

#if 0
    OE_PrintStruct(&MyFunctionArgs_ti, a);
#endif

    TEST(!OE_SetArgByName(ti, a, "str", 0, str, malloc));
    TEST(!OE_SetArgByName(ti, a, "u32", 0, u32, malloc));
    TEST(!OE_SetArgByName(ti, a, "u32a", 0, u32a, malloc));
    TEST(!OE_SetArgByName(ti, a, "stra", 0, stra, malloc));
    TEST(!OE_ClearArgByName(ti, a, "objp", 0, objp, free));
    TEST(!OE_SetArgByName(ti, a, "objp", 0, objp, malloc));
    TEST(!OE_ClearArgByName(ti, a, "objr", 1, objr, free));
    TEST(!OE_SetArgByName(ti, a, "objr", 1, objr, malloc));

    OE_FreeStruct(ti, a, free);

    return 0;
}

static int TestParams(bool trace)
{
    uint32_t u32 = 99;

    char str[256];
    size_t nstr = sizeof(str);
    strcpy(str, "This is my 'str'");

    uint32_t u32a[4] = {1, 2, 3, 4};

    char stra[32];
    strcpy(stra, "stra");

    CXXObject obj(1, "obj");

    CXXObject* objp = new CXXObject(2, "objp");
    TEST(objp);

    CXXObject* objr = new CXXObject(3, "objr");
    TEST(objr);

    if (MyFunction(
            "cstr", str, nstr, &u32, u32a, stra, obj, objp, (Object**)&objr) !=
        0)
    {
        OE_PutErr("MyFunction() failed");
    }

    TEST(strcmp(str, "aaaaaaaaaaaaaaaaaaaaaa") == 0);
    TEST(u32 == 66);
    TEST(u32a[0] == 10);
    TEST(strcmp(stra, "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz") == 0);
    TEST(objp->id = 11111111);
    TEST(objr->id = 22222222);

    delete objp;
    delete objr;

    printf("=== passed TestParams()\n");
    return 0;
}

int main(int argc, const char* argv[])
{
    OE_SetProgramName(argv[0]);
    bool trace = false;

    if (TestObject(trace) != 0)
        return 1;

    if (TestContainer(trace) != 0)
        return 1;

    if (TestCopyOver(trace) != 0)
        return 1;

#if 1
    if (TestAllTypes(trace) != 0)
        return 1;
#endif

    if (TestParams(trace) != 0)
        return 1;

    printf("=== passed all tests (typeinfo)\n");

    return 0;
}
