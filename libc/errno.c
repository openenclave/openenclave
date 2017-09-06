#include <errno.h>
#include <pthread.h>
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/sgxtypes.h>

int *__errno_location()
{
    TD* td = (TD*)OE_GetThreadData();
    assert(td);
    return &td->linux_errno;
}
