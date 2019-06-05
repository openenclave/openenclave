#include <openenclave/enclave.h>
#include "$projectname$_t.h"

int ecall_DoWorkInEnclave(void)
{
    /* Implement your ECALL here. */
    oe_result_t result = ocall_DoWorkInHost();
    return (result != OE_OK);
}

/* Add implementations of any other ECALLs here. */
