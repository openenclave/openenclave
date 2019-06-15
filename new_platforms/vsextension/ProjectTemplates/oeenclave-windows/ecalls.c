#include <openenclave/enclave.h>
#include <stdio.h>
#include "$projectname$_t.h"

int ecall_DoWorkInEnclave(void)
{
    /* Implement your ECALL here. */
    printf("Hello from within ecall_DoWorkInEnclave\n");
    oe_result_t result = ocall_DoWorkInHost();
    return (result != OE_OK);
}

/* Add implementations of any other ECALLs here. */
