#include <openenclave/enclave.h>

OE_SET_ENCLAVE_SGX(
    0, /* ProductID */
    0, /* SecurityVersion */
    true, /* AllowDebug */
    512, /* HeapPageCount */
    512,  /* StackPageCount */
    16);   /* TCSCount */
