#include <unistd.h>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <assert.h>
#include <pthread.h>
#include <openenclave/host.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/utils.h>
#include "../args.h"

static TestMutexArgs _args;

const size_t NUM_THREADS = 8;

void* Thread(void* args)
{
    OE_Enclave* enclave = (OE_Enclave*)args;

    OE_Result result = OE_CallEnclave(enclave, "TestMutex", &_args);
    assert(result == OE_OK);

    return NULL;
}

void TestMutex(OE_Enclave* enclave)
{
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, Thread, enclave);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    assert(_args.count == NUM_THREADS);
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
    pthread_t threads[NUM_THREADS];

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, WaiterThread, enclave);

    sleep(1);

    for (size_t i = 0; i < NUM_THREADS; i++)
        assert(OE_CallEnclave(enclave, "Signal", NULL) == OE_OK);

    for (size_t i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
}

/* Check consistency of OE/pthread mutex static-initializer layout */
void TestMutexLayoutConsistency()
{
    assert(sizeof(OE_Mutex) == sizeof(pthread_mutex_t));
    static pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
    static OE_Mutex m2 = OE_MUTEX_INITIALIZER;
    assert(memcmp(&m1, &m2, sizeof(pthread_mutex_t)) == 0);
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

    TestMutexLayoutConsistency();

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
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
