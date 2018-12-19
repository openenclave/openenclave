// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/tests.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "../args.h"

#define BROKEN

using namespace std;

size_t num_constructions;
size_t num_destructions;

static string _str;

class X
{
  public:
    X()
    {
    }

    virtual ~X()
    {
    }

    virtual void foo()
    {
    }
};

class Y : public X
{
  public:
    Y() : X()
    {
    }

    virtual ~Y()
    {
    }

    virtual void foo()
    {
    }
};

class G
{
  public:
    G()
    {
        num_constructions++;
        printf("G::G()\n");
    }

    ~G()
    {
        num_destructions++;
        printf("G::~G()\n");
    }
};

G _g0;
G _g1;
G _g2;

void MyAtExit()
{
    OE_TEST(num_constructions == 6);
    OE_TEST(num_destructions == 0);
    oe_host_printf("MyAtExit()\n");
}

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    if (!args)
        return;

    /* Register at-exit handler */
    oe_atexit(MyAtExit);

    /* Try strings */
    {
        string s = "hello world";
        s.find("world");
    }

    /* Try vectors */
    {
        vector<string> v;
        v.push_back("red");
        v.push_back("green");
        v.push_back("blue");

        if (v.size() != 3 || v[2] != "blue")
        {
            args->ret = -1;
            return;
        }

        v.clear();
    }

    /* Try maps */
    {
        map<string, int> m;
        m["red"] = 0;
        m["green"] = 1;
        m["blue"] = 2;

        if (m["blue"] != 2)
        {
            args->ret = -1;
            return;
        }
    }

    /* Try new/delete */
    {
        char* p = new char[12];

        if (!p)
        {
            args->ret = -1;
            return;
        }

        strcpy(p, "hello");

        if (strcmp(p, "hello") != 0)
        {
            args->ret = -1;
            return;
        }

        delete[] p;
    }

    /* Test virtual destructors */
    {
        X* x = new Y;

        delete x;
    }

    /* Test stringstream */
    {
        stringstream os;
        os << "hello";

        string s;
        os >> s;

        OE_TEST(s == "hello");
    }

    /* Test exceptions */
    {
        struct E
        {
            int x;
        };

        try
        {
            args->caught = false;
            throw E();
        }
        catch (const E& e)
        {
            args->caught = true;
        }
    }

    /* Test RTTI */
    {
        args->dynamic_cast_works = false;

        X* x = new Y;

        Y* y = dynamic_cast<Y*>(x);

        if (y)
            args->dynamic_cast_works = true;

        delete x;
    }

    args->num_constructions = num_constructions;

    args->ret = 0;
}

__attribute__((constructor)) void Constructor(void)
{
    oe_host_printf("Constructor()\n");
    OE_TEST(num_constructions == 0);
}

__attribute__((destructor)) void Destructor(void)
{
    oe_host_printf("Destructor()\n");
    OE_TEST(num_constructions == 6);
    OE_TEST(num_destructions == 6);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    512,  /* HeapPageCount */
    512,  /* StackPageCount */
    2);   /* TCSCount */

OE_DEFINE_EMPTY_ECALL_TABLE();
