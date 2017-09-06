#include <unistd.h>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <pthread.h>
#include <openenclave/host.h>
#include "../args.h"

static TestMutexArgs _args;

void* Thread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_Result result = OE_CallEnclave(enclave, "TestMutex", &_args);
    assert(result == OE_OK);

    return NULL;
}

void TestMutex(OE_Enclave* enclave)
{
    size_t N = 8;
    pthread_t threads[N];

    for (size_t i = 0; i < N; i++)
        pthread_create(&threads[i], NULL, Thread, enclave);

    for (size_t i = 0; i < N; i++)
        pthread_join(threads[i], NULL);

    assert(_args.count == 8);
}

void* WaiterThread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_Result result = OE_CallEnclave(enclave, "Wait", NULL);
    assert(result == OE_OK);

    return NULL;
}

void TestCond(OE_Enclave* enclave)
{
    size_t N = 8;
    pthread_t threads[N];

    for (size_t i = 0; i < N; i++)
        pthread_create(&threads[i], NULL, WaiterThread, enclave);

    sleep(1);

    for (size_t i = 0; i < N; i++)
        assert(OE_CallEnclave(enclave, "Signal", NULL) == OE_OK);

    for (size_t i = 0; i < N; i++)
        pthread_join(threads[i], NULL);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    if ((result = OE_CreateEnclave(argv[1], CREATE_FLAGS, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestMutex(enclave);

    TestCond(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
