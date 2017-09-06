#include <openenclave/enclave.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/globals.h>
#include "../args.h"

OE_ECALL void Test2(void* args_)
{
#if 0
    *((int*)0) = 0;
#endif
    Test2Args* args = (Test2Args*)args_;
    args->out = args->in;
}

OE_ECALL void TestAllocator(void* args_)
{
    TestAllocatorArgs* args = (TestAllocatorArgs*)args_;
    int i;
    int sum1 = 0;
    int sum2 = 0;
    typedef struct _Node
    {
        int num;
        struct _Node* next;
    }
    Node;
    Node* head = nullptr;
    Node* p;

    if (!args)
    {
        args->ret = -1;
        return;
    }

    /* Allocate the nodes */
    for (i = 0; i < 100; i++)
    {
        Node* node;

        if (!(node = (Node*)OE_Malloc(sizeof(Node))))
        {
            args->ret = -1;
            return;
        }

        node->num = i;
        node->next = head;
        head = node;
        sum1 += i;
    }

    /* Traverse the list */
    for (p = head; p; p = p->next)
    {
        sum2 += p->num;
    }

    if (sum1 != sum2)
    {
        args->ret = -1;
        return;
    }

    /* Release the nodes */
    for (p = head; p; )
    {
        Node* next = p->next;
        OE_Free(p);
        p = next;
    }

    args->ret = 0;
}

OE_ECALL void Test3(void* args_)
{
    Func1Args* func1Args;

    if (!(func1Args = (Func1Args*)OE_Malloc(sizeof(Func1Args))))
        return;

    OE_Strcpy(func1Args->buf, "Func1");

    if (OE_CallHost("Func1", func1Args) != OE_OK)
        return;
}

OE_ECALL void Test4(void* args)
{
    unsigned char buf[32];

    /* Call into host with enclave memory */
    OE_Memset(buf, 0xAA, sizeof(buf));

    if (OE_CallHost("Func2", buf) != OE_OK)
    {
        OE_Abort();
        return;
    }
}

static OE_OnceType _once = OE_ONCE_INITIALIZER;
static OE_ThreadKey _key = OE_THREADKEY_INITIALIZER;

static void _init()
{
    if (OE_ThreadKeyCreate(&_key, OE_NULL) != 0)
        OE_Abort();
}

OE_ECALL void SetTSD(void* args_)
{
    SetTSDArgs* args = (SetTSDArgs*)args_;

    if (!args)
        OE_Abort();

    /* Initialize this the first time */
    if (OE_Once(&_once, _init) != 0)
    {
        args->ret = -1;
        return;
    }

    /* Set the thread-specific data */
    if (OE_ThreadSetSpecific(_key, args->value) != 0)
    {
        args->ret = -1;
        return;
    }

    args->ret = 0;
}

OE_ECALL void GetTSD(void* args_)
{
    GetTSDArgs* args = (GetTSDArgs*)args_;

    if (!args)
        OE_Abort();

    args->value = OE_ThreadGetSpecific(_key);
    args->ret = 0;
}
