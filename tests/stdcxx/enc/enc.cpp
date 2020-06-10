// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/tests.h>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "stdcxx_t.h"

#define BROKEN

using namespace std;

size_t num_constructions;
size_t num_destructions;

static string _str;

class x
{
  public:
    x()
    {
    }

    virtual ~x()
    {
    }

    virtual void foo()
    {
    }
};

class y : public x
{
  public:
    y() : x()
    {
    }

    virtual ~y()
    {
    }

    virtual void foo()
    {
    }
};

class g
{
  public:
    g()
    {
        num_constructions++;
        printf("g::g()\n");
    }

    ~g()
    {
        num_destructions++;
        printf("g::~g()\n");
    }
};

g _g0;
g _g1;
g _g2;

void my_at_exit()
{
    OE_TEST(num_constructions == 6);
    OE_TEST(num_destructions == 0);
    oe_host_printf("my_at_exit()\n");
}

int enc_test(bool* caught, bool* dynamic_cast_works, size_t* n_constructions)
{
    /* Register at-exit handler */
    oe_atexit(my_at_exit);

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
            return -1;
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
            return -1;
        }
    }

    /* Try new/delete */
    {
        char* p = new char[12];

        if (!p)
        {
            return -1;
        }

        strcpy(p, "hello");

        if (strcmp(p, "hello") != 0)
        {
            delete[] p;
            return -1;
        }

        delete[] p;
    }

    /* Test virtual destructors */
    {
        x* local_x = new y;

        delete local_x;
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
        struct e
        {
            int val;
        };

        try
        {
            *caught = false;
            throw e();
        }
        catch (const e&)
        {
            *caught = true;
        }
    }

    /* Test RTTI */
    {
        *dynamic_cast_works = false;

        x* local_x = new y;

        y* local_y = dynamic_cast<y*>(local_x);

        if (local_y)
        {
            *dynamic_cast_works = true;
        }

        delete local_x;
    }

    *n_constructions = num_constructions;

    /* Test std::bad_alloc */
    {
        bool bad_alloc_caught = false;
        std::vector<int*> ptrs;
        while (true)
        {
            try
            {
                int* p = new int[64];
                ptrs.push_back(p);
            }
            catch (std::bad_alloc&)
            {
                bad_alloc_caught = true;
                printf("std::bad_alloc caught\n");
                break;
            }
        }
        while (!ptrs.empty())
        {
            delete ptrs.back();
            ptrs.pop_back();
        }

        OE_TEST(bad_alloc_caught == true);
    }

    return 0;
}

__attribute__((constructor)) void constructor(void)
{
    oe_host_printf("constructor()\n");
    OE_TEST(num_constructions == 0);
}

__attribute__((destructor)) void destructor(void)
{
    oe_host_printf("destructor()\n");
    OE_TEST(num_constructions == 6);
    OE_TEST(num_destructions == 6);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    512,  /* NumStackPages */
    2);   /* NumTCS */
