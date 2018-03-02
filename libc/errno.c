#include <assert.h>
#include <errno.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/enclave.h>
#include <pthread.h>

int* __errno_location()
{
    TD* td = (TD*)OE_GetThreadData();
    assert(td);
    return &td->linux_errno;
}
