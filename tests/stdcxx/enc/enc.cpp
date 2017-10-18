#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <map>
#include <openenclave/enclave.h>
#include <openenclave/bits/globals.h>
#include "../args.h"

#define BROKEN

#if 0
# define T(EXPR)
#else
# define T(EXPR) EXPR
#endif

using namespace std;

static string _str;

static size_t _numConstructions;
static size_t _numDestructions;

class E
{
public:
    E()
    {
        T( OE_HostPrintf("E::E()\n"); )
        _numConstructions++;
    }
    ~E()
    {
        T( OE_HostPrintf("E::~E()\n"); )
        _numDestructions++;
    }
};

class G
{
public:

    G()
    {
        T( OE_HostPrintf("G::G()\n"); )
        _numConstructions++;
    }
    ~G()
    {
        T( OE_HostPrintf("G::~G()\n"); )
        _numDestructions++;
    }

    E e;
};

static G _g0;
static G _g1;
static G _g2;
static G _g3;
static G _g4;
static G _g5;
static G _g6;
static G _g7;
static G _g8;
static G _g9;

class Object0
{
public:

    Object0()
    {
        T( OE_HostPrintf("Object0::Object0()\n"); )
    }
    ~Object0()
    {
        T( OE_HostPrintf("Object0::~Object0()\n"); )
    }
};

class Object1
{
public:

    Object1()
    {
        T( OE_HostPrintf("Object1::Object1()\n"); )
    }
    ~Object1()
    {
        T( OE_HostPrintf("Object1::~Object1()\n"); )
    }
};

Object0 o0;
Object1 o1;

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

    /* Test stringstream */
    {
        stringstream os;
        os << "hello";

        string s;
        os >> s;

        assert(s == "hello");
    }

    /* Test exceptions */
    {
        struct E { };

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
        args->dynamicCastWorks = false;

        X* x = new Y;

        Y* y = dynamic_cast<Y*>(x);

        if (y)
            args->dynamicCastWorks = true;
    }

    /* Check G() constructor call count */
    args->numConstructions = _numConstructions;

    args->ret = 0;
}
