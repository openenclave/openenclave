#include <openenclave/enclave.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include "../args.h"

#define BUFSIZE 1024
#define ITERS 1024

OE_ECALL void TestHostBoundaries(void* args_)
{
    Buffer* args = (Buffer*)args_;
    OE_TEST(oe_is_outside_enclave(args, sizeof(*args)));

    Buffer buf = *args;
    OE_TEST(oe_is_outside_enclave(buf.buf, buf.size));
}

OE_ECALL void TestEnclaveBoundaries(void* args_)
{
    void* array[ITERS];
    for (int i = 0; i < ITERS; i++)
    {
        array[i] = malloc(BUFSIZE);
        OE_TEST(array[i] != NULL);
        OE_TEST(oe_is_within_enclave(array[i], BUFSIZE));
    }

    for (int i = 0; i < ITERS; i++)
        free(array[i]);
}

OE_ECALL void TestBetweenEnclaveBoundaries(void* args)
{
    BoundaryArgs* bargs_ = (BoundaryArgs*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    BoundaryArgs bargs = *bargs_;

    /* Ensure that buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs.hostStack.buf, bargs.hostStack.size));
    OE_TEST(oe_is_outside_enclave(bargs.hostHeap.buf, bargs.hostHeap.size));

    unsigned char* stackbuf = bargs.hostStack.buf;
    unsigned char* heapbuf = bargs.hostHeap.buf;

    /* Verify host stack and heap pointers work. */
    for (int i = 0; i < bargs.hostStack.size; i++)
        OE_TEST(stackbuf[i] == 1);

    for (int i = 0; i < bargs.hostHeap.size; i++)
        OE_TEST(heapbuf[i] == 2);

    /* Send two pointers. One from malloc (enclave memory) and
     * one from `oe_host_malloc` (host memory). */
    bargs.enclaveMemory.buf = (unsigned char*)malloc(BUFSIZE);
    OE_TEST(bargs.enclaveMemory.buf != NULL);
    OE_TEST(oe_is_within_enclave(bargs.enclaveMemory.buf, BUFSIZE));
    bargs.enclaveMemory.size = BUFSIZE;
    for (int i = 0; i < bargs.enclaveMemory.size; i++)
        bargs.enclaveMemory.buf[i] = 3;

    bargs.enclaveHostMemory.buf = (unsigned char*)oe_host_malloc(BUFSIZE);
    OE_TEST(bargs.enclaveHostMemory.buf != NULL);
    OE_TEST(oe_is_outside_enclave(bargs.enclaveHostMemory.buf, BUFSIZE));
    bargs.enclaveHostMemory.size = BUFSIZE;
    for (int i = 0; i < bargs.enclaveHostMemory.size; i++)
        bargs.enclaveHostMemory.buf[i] = 4;

    bargs_->enclaveMemory = bargs.enclaveMemory;
    bargs_->enclaveHostMemory = bargs.enclaveHostMemory;
}

OE_ECALL void TryInputEnclavePointer(void* args)
{
    BoundaryArgs* bargs_ = (BoundaryArgs*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    BoundaryArgs bargs = *bargs_;

    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(
        oe_is_within_enclave(
            bargs.enclaveMemory.buf, bargs.enclaveMemory.size));

    /* Verify enclave memory is unchanged. */
    for (int i = 0; i < bargs.enclaveMemory.size; i++)
        OE_TEST(bargs.enclaveMemory.buf[i] == 3);
}

OE_ECALL void FreeBoundaryMemory(void* args)
{
    BoundaryArgs* bargs_ = (BoundaryArgs*)args;
    if (!bargs_)
        return;

    /* Ensure host buffers are outside the enclave. */
    OE_TEST(oe_is_outside_enclave(bargs_, sizeof(*bargs_)));

    BoundaryArgs bargs = *bargs_;

    /* Ensure that enclave buffer is in the enclave. */
    OE_TEST(
        oe_is_within_enclave(
            bargs.enclaveMemory.buf, bargs.enclaveMemory.size));

    free(bargs.enclaveMemory.buf);
    oe_host_free(bargs.enclaveHostMemory.buf);
}
