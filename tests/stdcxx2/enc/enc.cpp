#include <enc/enclave.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <map>
#include "../args.h"

using namespace std;

class X
{
public:
    X() : _x(0)
    {
    }
    
    virtual ~X()
    {
    }

    virtual void foo()
    {
    }

private:
    int _x;
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

OE_ECALL void Test(void* args_)
{
    TestArgs* args = (TestArgs*)args_;

    if (!args)
        return;

#if 0
    /* Vectors */
    {
        vector<int> v;
        v.push_back(10);
        v.push_back(20);
        v.push_back(30);
    }

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
        map<string,int> m;
        m["red"] = 0;
        m["green"] = 1;
        m["blue"] = 2;

        if (m["blue"] != 2)
        {
            args->ret = -1;
            return;
        }
    }
#endif

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

        delete [] p;
    }

    /* Test virtual destructors */
    {
        X* x = new Y;

        delete x;
    }

    /* Test RTTI */
    {
        X* x = new Y;
        Y* y = dynamic_cast<Y*>(x);

        if (!y)
        {
            args->ret = -1;
            return;
        }
    }

#if 1
    /* Test exceptions */
    {
        struct X { };

        try
        {
            throw X();
            args->ret = -1;
        }
        catch (X)
        {
            args->ret = 0;
        }
    }
#endif

#if 0
    stringstream os;
    os << "hello" << endl;
#endif
    
    args->ret =0;
}

void operator delete(void* ptr)
{
    free(ptr);
}

void operator delete[](void* ptr)
{
    free(ptr);
}

void* operator new(size_t size)
{
    return malloc(size);
}

void* operator new[](size_t size)
{
    return malloc(size);
}
