#include <stdio.h>
#include "$projectname$_t.h"

#define HEAP_SIZE_BYTES (2 * 1024 * 1024) /* 2 MB */
#define STACK_SIZE_BYTES (24 * 1024)      /* 24 KB */

#define SGX_PAGE_SIZE (4 * 1024) /* 4 KB */

#define TA_UUID /* $guid1$ */ $guid1struct$

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,                                  /* UUID */
    HEAP_SIZE_BYTES,                          /* HEAP_SIZE */
    STACK_SIZE_BYTES,                         /* STACK_SIZE */
    TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR, /* FLAGS */
    "1.0.0",                                  /* VERSION */
    "$projectname$ TA");                      /* DESCRIPTION */

OE_SET_ENCLAVE_SGX(
    1, /* ProductID */
    1, /* SecurityVersion */
#ifdef _DEBUG
    1, /* Debug */
#else
    0, /* Debug */
#endif
    HEAP_SIZE_BYTES / SGX_PAGE_SIZE,  /* NumHeapPages */
    STACK_SIZE_BYTES / SGX_PAGE_SIZE, /* NumStackPages */
    1);                               /* NumTCS */

int ecall_DoWorkInEnclave(void)
{
    /* Implement your ECALL here. */
    printf("Hello from within ecall_DoWorkInEnclave\n");
    oe_result_t result = ocall_DoWorkInHost();
    return (result != OE_OK);
}

/* Add implementations of any other ECALLs here. */
