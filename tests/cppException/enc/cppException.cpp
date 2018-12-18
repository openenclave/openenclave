// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <exception>
#include <string>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wexceptions"
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wterminate"
#endif

using namespace std;

class BarClass01
{
  public:
    BarClass01(int _i) : i(_i)
    {
    }
    BarClass01(BarClass01& other) : i(other.i)
    {
    }

    int i;
};

class BarClass02 : std::exception
{
  public:
    BarClass02(int _i) : i(_i)
    {
    }
    BarClass02(BarClass02& other) : i(other.i)
    {
    }

    int i;
};

class BarClass03 : public BarClass02
{
  public:
    BarClass03(int _i) : BarClass02(_i)
    {
    }
    BarClass03(BarClass03& other) : BarClass02(other.i)
    {
    }
};

// Verify if basic types (char, int, string, class, derived class from
// std::exception) can be thrown and caught correctly.
bool BasicVerification()
{
    // char type exception.
    try
    {
        char ch = 'x';
        throw ch;
    }
    catch (char ex_ch)
    {
        if (ex_ch != 'x')
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("char type exception tests passed.\n");

    // integer type exception.
    try
    {
        int i = 0XFFEE;
        throw i;
    }
    catch (char)
    {
        return false;
    }
    catch (int ex_i)
    {
        if (ex_i != 0XFFEE)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("integer type exception tests passed.\n");

    // string type exception.
    try
    {
        string str = "STR EXCEPTION";
        throw str;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string ex_str)
    {
        if (ex_str != "STR EXCEPTION")
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("string type exception tests passed.\n");

    // string type exception caught by reference.
    try
    {
        string str = "STR EXCEPTION";
        throw str;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string& ex_str)
    {
        if (ex_str != "STR EXCEPTION")
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("string reference type exception tests passed.\n");

    // user defined class type exception.
    try
    {
        BarClass01 obj(0XFFFF);
        throw obj;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string)
    {
        return false;
    }
    catch (BarClass01 ex_obj)
    {
        if (ex_obj.i != 0XFFFF)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("user defined class type exception tests passed.\n");

    // user defined class type exception caught by reference.
    try
    {
        BarClass01 obj(0XFFFF);
        throw obj;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string)
    {
        return false;
    }
    catch (BarClass01& ex_obj)
    {
        if (ex_obj.i != 0XFFFF)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf(
        "user defined class reference type exception tests passed.\n");

    // user defined class type exception should not caught by incompatible
    // class, but caught by the same class type.
    try
    {
        BarClass02 obj(0XFFFFF);
        throw obj;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string)
    {
        return false;
    }
    catch (BarClass01)
    {
        return false;
    }
    catch (BarClass02 ex_obj)
    {
        if (ex_obj.i != 0XFFFFF)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("user defined class type exception test passed.\n");

    // user defined class type exception should not caught by incompatible
    // class, but caught by the same reference class type.
    try
    {
        BarClass02 obj(0XFFFFF);
        throw obj;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string)
    {
        return false;
    }
    catch (BarClass01)
    {
        return false;
    }
    catch (BarClass02& ex_obj)
    {
        if (ex_obj.i != 0XFFFFF)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf(
        "user defined class reference type exception test passed.\n");

    // user defined class type exception should not caught by incompatible
    // class, but caught by the base class type.
    try
    {
        BarClass03 obj(0XFFFFFF);
        throw obj;
    }
    catch (char)
    {
        return false;
    }
    catch (int)
    {
        return false;
    }
    catch (string)
    {
        return false;
    }
    catch (BarClass01)
    {
        return false;
    }
    catch (BarClass02 ex_obj)
    {
        if (ex_obj.i != 0XFFFFFF)
        {
            return false;
        }
    }
    catch (...)
    {
        return false;
    }

    oe_host_printf("user defined class type exception test passed.\n");
    return true;
}

// Verify catch ellipsis can catch everything.
bool EllipsisCatch()
{
    int ex_count = 0;

    // char type exception can be caught.
    try
    {
        char ch = 'x';
        throw ch;
    }
    catch (...)
    {
        ex_count++;
    }

    // integer type exception can be caught.
    try
    {
        int i = 0XFFEE;
        throw i;
    }
    catch (...)
    {
        ex_count++;
    }

    // string type exception can be caught.
    try
    {
        string str = "STR EXCEPTION";
        throw str;
    }
    catch (...)
    {
        ex_count++;
    }

    // user defined class type exception can be caught.
    try
    {
        BarClass01 obj(0XFFFF);
        throw obj;
    }
    catch (...)
    {
        ex_count++;
    }

    // std::exception derived class type exception can be caught.
    try
    {
        BarClass02 obj(0XFFFFF);
        throw obj;
    }
    catch (...)
    {
        ex_count++;
    }

    oe_host_printf("Ellipsis exception catch tests passed.\n");
    return true;
}

void bar02()
{
    try
    {
        BarClass02 obj(0XFFFFF);
        throw obj;
    }
    catch (BarClass03)
    {
        return;
    }
}

void bar01()
{
    try
    {
        bar02();
    }
    catch (BarClass01)
    {
        return;
    }
}

// Nested
bool NestedException()
{
    // Re-throw and throw new exception in the catch clause.
    try
    {
        BarClass01 obj(0XF);
        throw obj;
    }
    catch (BarClass01 ex_obj)
    {
        if (ex_obj.i != 0XF)
        {
            return false;
        }

        try
        {
            throw;
        }
        catch (BarClass01& ex_obj)
        {
            if (ex_obj.i != 0XF)
            {
                return false;
            }
        }

        try
        {
            BarClass02 obj(0XFF);
            throw obj;
        }
        catch (BarClass02& ex_obj)
        {
            if (ex_obj.i != 0XFF)
            {
                return false;
            }
        }
    }

    oe_host_printf(
        "Re-throw and throw new exception in the catch clause tests passed.\n");

    // Find the matching catch clause in the outermost block.
    try
    {
        try
        {
            try
            {
                BarClass02 obj(0XFFFF);
                throw obj;
            }
            catch (int)
            {
                return false;
            }
        }
        catch (BarClass01)
        {
            return false;
        }
    }
    catch (BarClass02 ex_obj)
    {
        if (ex_obj.i != 0XFFFF)
        {
            return false;
        }
    }

    oe_host_printf("catch clause in the outermost block tests passed.\n");

    // Find the matching catch clause through call stack.
    try
    {
        bar01();
        return false;
    }
    catch (BarClass02& ex_obj)
    {
        if (ex_obj.i != 0XFFFFF)
        {
            return false;
        }
    }

    oe_host_printf(
        "Find the matching catch clause through call stack tests passed.\n");
    return true;
}

// Throw an exception despite this function claims no exception will be thrown.
// The expected behavior is abort function is called, and the whole process
// will be terminated.
void bar03() noexcept(true)
{
    throw 'X';
}

bool ExceptionSpecification()
{
    try
    {
        bar03();
    }
    catch (...)
    {
        return false;
    }

    return false;
}

static int g_barclass0501_count = 0;

class BarClass0501
{
  public:
    BarClass0501()
    {
        g_barclass0501_count++;
    }

    ~BarClass0501()
    {
        g_barclass0501_count--;
    }
};

static int g_barclass05_count = 0;

class BarClass05
{
  public:
    BarClass05()
    {
        g_barclass05_count++;
    }

    ~BarClass05()
    {
        g_barclass05_count--;
    }

  private:
    BarClass0501 obj;
};

static int g_barclass06_count = 0;

class BarClass06 : public BarClass05
{
  public:
    BarClass06()
    {
        g_barclass06_count++;
    }

    ~BarClass06()
    {
        g_barclass06_count--;
    }
};

static int g_barclass07_count = 0;

class BarClass07 : public BarClass06
{
  public:
    BarClass07()
    {
        g_barclass07_count++;
        throw 'X';
    }

    ~BarClass07()
    {
        g_barclass07_count--;
    }
};

bool foo01()
{
    BarClass05 obj;
    if (g_barclass05_count != 1 || g_barclass0501_count != 1)
    {
        return false;
    }

    BarClass06 obj2;
    if (g_barclass05_count != 2 || g_barclass0501_count != 2 ||
        g_barclass06_count != 1)
    {
        return false;
    }

    throw 'X';
}

bool foo02()
{
    BarClass05 obj[10];
    if (g_barclass0501_count != 10 || g_barclass05_count != 10)
    {
        return false;
    }

    BarClass06 obj2[10];
    if (g_barclass0501_count != 20 || g_barclass05_count != 20 ||
        g_barclass06_count != 10)
    {
        return false;
    }

    throw 'X';
}

bool foo03(int i)
{
    try
    {
        if (i > 0)
        {
            foo01();
        }
        else
        {
            foo02();
        }

        return false;
    }
    catch (int)
    {
        return false;
    }

    return false;
}

// Stack unwinding.
bool StackUnwind()
{
    // class, its member, and base class should be destroyed in local unwind.
    try
    {
        BarClass05 obj;
        if (g_barclass05_count != 1 || g_barclass0501_count != 1)
        {
            return false;
        }

        BarClass06 obj2;
        if (g_barclass05_count != 2 || g_barclass0501_count != 2 ||
            g_barclass06_count != 1)
        {
            return false;
        }

        throw 'X';
    }
    catch (char)
    {
        if (g_barclass0501_count != 0 || g_barclass05_count != 0 ||
            g_barclass06_count != 0)
        {
            return false;
        }
    }

    oe_host_printf("StackUnwind local unwind test passed.\n");

    // class, its member, and base class should be destroyed in global unwind.
    try
    {
        foo03(1);
        return false;
    }
    catch (char)
    {
        if (g_barclass0501_count != 0 || g_barclass05_count != 0 ||
            g_barclass06_count != 0)
        {
            return false;
        }
    }

    oe_host_printf("StackUnwind global unwind test passed.\n");

    // array of class, its member, and base class should be destroyed in local
    // unwind.
    try
    {
        BarClass05 obj[10];
        if (g_barclass0501_count != 10 || g_barclass05_count != 10)
        {
            return false;
        }

        BarClass06 obj2[10];
        if (g_barclass0501_count != 20 || g_barclass05_count != 20 ||
            g_barclass06_count != 10)
        {
            return false;
        }

        throw 'X';
    }
    catch (char)
    {
        if (g_barclass0501_count != 0 || g_barclass05_count != 0 ||
            g_barclass06_count != 0)
        {
            return false;
        }
    }

    oe_host_printf("StackUnwind local unwind second test passed.\n");

    // array of class, its member, and base class should be destroyed in global
    // unwind.
    try
    {
        foo03(0);
        return false;
    }
    catch (char)
    {
        if (g_barclass0501_count != 0 || g_barclass05_count != 0 ||
            g_barclass06_count != 0)
        {
            return false;
        }
    }

    oe_host_printf("StackUnwind global unwind second test passed.\n");

    // Exception happens in the constructor, the destructor of base class will
    // be called, and the destructor of itself will not be called.
    try
    {
        BarClass07 obj;
    }
    catch (char)
    {
        if (g_barclass0501_count != 0 || g_barclass05_count != 0 ||
            g_barclass06_count != 0 || g_barclass07_count != 1)
        {
            return false;
        }
    }

    oe_host_printf("StackUnwind unwind test passed.\n");
    return true;
}

class BarClass08 : public std::exception
{
  public:
    BarClass08()
    {
    }

    ~BarClass08() throw()
    {
        throw "X";
    }
};

bool ExceptionInUnwind()
{
    try
    {
        // Will throw an exception when stack unwinding.
        // The expected behavior is abort function is called, and the whole
        // process
        // will be terminated.
        BarClass08 obj;
        throw 'X';
    }
    catch (...)
    {
        return false;
    }

    return true;
}

static bool g_bar04_status = false;

void bar04() try
{
    throw 'X';
}
catch (char ex_ch)
{
    g_bar04_status = (ex_ch == 'X');
}

static int g_barclass09_count = 0;

class BarClass09
{
  public:
    BarClass09()
    {
        g_barclass09_count++;
    }

    ~BarClass09()
    {
        g_barclass09_count--;
    }
};

static int g_barclass10_count = 0;

class BarClass10
{
  public:
    BarClass10()
    {
        g_barclass10_count++;
    }

    ~BarClass10()
    {
        g_barclass10_count--;
    }
};

class BarClass11 : public BarClass10
{
  public:
    BarClass11(int i) try
    {
        if (i < 0)
        {
            throw 'X';
        }
    }
    catch (char ex_ch)
    {
        if (ex_ch != 'X')
        {
            throw 0XFF;
        }
    }

    ~BarClass11()
    {
    }

  private:
    BarClass09 bar09;
};

bool FunctionTryBlock()
{
    // Verify if the exception happens in function-try-block is handled.
    bar04();
    if (g_bar04_status == false)
    {
        return false;
    }

    try
    {
        BarClass11 obj(-1);
        return false;
    }
    catch (char ex_ch)
    {
        // Verify if
        // 1) Get the original exception happens in function-try-block.
        // 2) Destructor of base class is called correctly.
        // 3) Destructor of class member is called correctly.
        if (ex_ch != 'X' || g_barclass10_count != 0 || g_barclass10_count != 0)
        {
            return false;
        }
    }

    oe_host_printf("FunctionTryBlock exception test passed.\n");

    return true;
}

bool UnhandledException()
{
    try
    {
        int i = 0XFFFF;
        throw i;
    }
    catch (char)
    {
        return false;
    }

    return false;
}

bool TestCppException()
{
    return (
        BasicVerification() && EllipsisCatch() && NestedException() &&
        StackUnwind() && FunctionTryBlock());
}
