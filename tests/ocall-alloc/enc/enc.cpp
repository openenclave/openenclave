// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
   Testing oe_host_alloc_for_call_host()
   - Regular nesting / un-nesting
   - Whitebox-tests w/ tracking of allocation/de-allocation
 */

#define OE_TRACE_LEVEL 1

#include <openenclave/enclave.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <openenclave/internal/trace.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stack>
#include "../args.h"
#include "wrap.h"

// simple xor-shift generator
struct XorShift
{
    XorShift(uint32_t seed) : Seed(seed){};
    uint32_t operator()()
    {
        /* Algorithm "xor" from p. 4 of Marsaglia, "xor-shift RNGs" */
        uint32_t x = Seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        Seed = x;
        return x;
    }

  private:
    uint32_t Seed;
};

// allocation record for tracking stack allocations
struct Allocation
{
    unsigned size;
    void* addr;
    unsigned seed;
};
typedef std::stack<Allocation> AllocStack;

// fill range with semi-random pattern
void FillRnd(const Allocation& allocation)
{
    XorShift rnd(allocation.seed);

    uint32_t* addr = (uint32_t*)allocation.addr;
    uint32_t size = allocation.size;
    while (size > sizeof(uint32_t))
    {
        *addr = rnd();
        addr++;
        size -= sizeof(uint32_t);
    }
    if (size > 0)
    {
        uint32_t val = rnd();
        memcpy(addr, &val, size);
    }
}

// Verify pattern, returns 0 on success
int VerifyRnd(const Allocation& allocation)
{
    XorShift rnd(allocation.seed);

    uint32_t* addr = (uint32_t*)allocation.addr;
    uint32_t size = allocation.size;
    while (size > sizeof(uint32_t))
    {
        if (*addr != rnd())
            return 1;
        addr++;
        size -= sizeof(uint32_t);
    }
    if (size > 0)
    {
        uint32_t val = rnd();
        return memcmp(addr, &val, size);
    }
    return 0;
}

// an allocator to facilitate native & intercepted versions
struct Allocator
{
    void* (*alloc)(size_t size);
    void (*free)(void* p);
};

// allocate chunks of bytes using allocator, track in stack
static void Alloc(
    AllocStack& stack,
    unsigned size,
    unsigned count,
    const Allocator& alloc)
{
    static unsigned counter = 1;
    for (unsigned i = 0; i < count; i++)
    {
        OE_TRACE_INFO("Allocating %d/%d: %x bytes\n", i + 1, count, size);
        void* p = alloc.alloc(size);
        OE_TRACE_INFO("  Allocated %p\n", p);
        FillRnd({size, p, counter});
        stack.push({size, p, counter});
        if (++counter == 0)
            counter = 1;
    }
}

// free chunks of bytes using allocator, data from stack
static void Dealloc(AllocStack& stack, unsigned count, const Allocator& alloc)
{
    for (unsigned i = 0; i < count; i++)
    {
        OE_TRACE_INFO("Freeing %d/%d: %p\n", i + 1, count, stack.top().addr);
        OE_TEST(!VerifyRnd(stack.top()));
        alloc.free(stack.top().addr);
        OE_TRACE_INFO("  Freed %p\n", stack.top().addr);
        stack.pop();
    }
}

// alloc + free chunks of bytes using allocator, track in stack
static void AllocDealloc(
    AllocStack& stack,
    unsigned size,
    unsigned count,
    const Allocator& alloc)
{
    Alloc(stack, size, count, alloc);
    Dealloc(stack, count, alloc);
}

//
// Command array w/ simple language:
// 'a' <size> [<count>] - allocate
// 'd' [<count>] - deallocate
// 't' - simulate terminate (call exit-handlers)
// 'v' <count> <bytes> - verify backing memory allocations
// 'x' <size> [<count>] - alloc(size,count)/dealloc(size,count)
//
typedef struct Cmd
{
    char cmd;
    uint32_t val1;
    uint32_t val2;
} Cmd;

static Cmd Commands[] = {
    {'v', 0, 0},
    {'x', 0},
    {'v', 0, 0},

    {'x', 5, 20},
    {'v', 0x1000, 1},
    {'x', 1024, 20},

    {'v', 0x2000, 2},

    {'a', 1024},
    {'v', 0x2000, 2},
    {'x', 5, 20},
    {'a', 1024, 20},
    {'v', 0x7000, 7},
    {'d', 20},
    {'v', 0x2000, 2},
    {'d'},

    {'v', 0x2000, 2},

    {'x', 5, 20},
    {'x', 1024, 20},
    {'x', 1024, 20},
    {'v', 0x2000, 2},
    {'a', 0xFE8, 2},
    {'v', 0x2000, 2},
    {'a', 0xFE9, 2},
    {'v', 0x4002, 4},
    {'d', 4},

    {'v', 0x2000, 2},

    {'a', 1024, 20},
    {'v', 0x7000, 7},
    {'a', 1024 * 1024},
    {'v', 0x107018, 8},
    {'d'},
    {'x', 1024, 20},
    {'d', 20},

    {'v', 0x2000, 2},

    {'t'},
    {'v', 0, 0},
    {'x', 0x1000, 2},
    {'v', 0, 0},
};

// Command interpreter for above array - actual test driver
oe_result_t TestRun(bool doVerifyAllocation, const Allocator alloc)
{
    AllocStack stack;

    for (const Cmd& cmd : Commands)
    {
        switch (cmd.cmd)
        {
            case 'a':
                Alloc(stack, cmd.val1, cmd.val2 ?: 1, alloc);
                break;
            case 'd':
                Dealloc(stack, cmd.val1 ?: 1, alloc);
                break;
            case 't':
                if (!doVerifyAllocation)
                    break;
                Exit();
                break;
            case 'v':
                if (!doVerifyAllocation)
                    break;

                if ((GetAllocationBytes() != cmd.val1 ||
                     GetAllocationCount() != cmd.val2))
                {
                    printf(
                        "Expected %#x bytes allocated in %u chunks, have %#lx "
                        "bytes in %llu chunks.\n",
                        cmd.val1,
                        cmd.val2,
                        GetAllocationBytes(),
                        OE_LLU(GetAllocationCount()));
                    return OE_FAILURE;
                }
                break;
            case 'x':
                AllocDealloc(stack, cmd.val1, cmd.val2 ?: 1, alloc);
                break;
            default:
                printf("Unhandled command - %c\n", cmd.cmd);
                return OE_FAILURE;
        }
    }

    OE_TEST(stack.empty());

    return OE_OK;
}

OE_ECALL void TestAllocaDealloc(void* args)
{
    if (!oe_is_outside_enclave(args, sizeof(oe_result_t)))
        return;

    oe_result_t* result = (oe_result_t*)args;

    // test with native functions, no backing memory verification
    OE_TEST(
        TestRun(
            false, {oe_host_alloc_for_call_host, oe_host_free_for_call_host}) ==
        OE_OK);

    // test with wrapped functions tracking backing memory allocation
    OE_TEST(
        TestRun(
            true,
            {test_host_alloc_for_call_host, test_host_free_for_call_host}) ==
        OE_OK);

    *result = OE_OK;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    128,  /* StackPageCount */
    16);  /* TCSCount */
