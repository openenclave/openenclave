#include <openenclave.h>
#include <__openenclave/sgxtypes.h>
#include <__openenclave/globals.h>
#include <__openenclave/fault.h>
#include <__openenclave/globals.h>
#include "../args.h"

OE_ECALL void Test2(void* args_)
{
#if 0
    *((int*)0) = 0;
#endif
    Test2Args* args = (Test2Args*)args_;
    args->out = args->in;
}

#if 1
# define MALLOC malloc
# define FREE free
#else
# define MALLOC malloc_u
# define FREE free_u
#endif

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

        if (!(node = (Node*)MALLOC(sizeof(Node))))
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
        FREE(p);
        p = next;
    }

    args->ret = 0;
}

OE_ECALL void Test3(void* args_)
{
    Func1Args* func1Args;

    if (!(func1Args = (Func1Args*)malloc_u(sizeof(Func1Args))))
        return;

    strcpy(func1Args->buf, "Func1");

    if (OE_CallHost("Func1", func1Args) != OE_OK)
        return;
}

OE_ECALL void Test4(void* args)
{
    unsigned char buf[32];

    /* Call into host with enclave memory */
    memset(buf, 0xAA, sizeof(buf));

    if (OE_CallHost("Func2", buf) != OE_OK)
    {
        abort();
        return;
    }
}

static OE_OnceType _once = OE_ONCE_INITIALIZER;
static OE_ThreadKey _key = OE_THREADKEY_INITIALIZER;

static void _init()
{
    if (OE_ThreadKeyCreate(&_key, NULL) != 0)
        abort();
}

OE_ECALL void SetTSD(void* args_)
{
    SetTSDArgs* args = (SetTSDArgs*)args_;

    if (!args)
        abort();

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
        abort();

    args->value = OE_ThreadGetSpecific(_key);
    args->ret = 0;
}
