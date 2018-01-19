#include <openenclave/enclave.h>
#include <openenclave/bits/enclavelibc.h>
#include "../args.h"

OE_ECALL void GetReport(void* args_)
{
    Args* args = (Args*)args_;
    Args copy;

    if (!args_)
        return;

    /* Copy the arguments into enclave memory */
    copy = *args;

    /* Generate the report */
    if ((args->result = SGX_CreateReport(
        &copy.targetInfo, &copy.reportData, &copy.report)) != OE_OK)
    {
        return;
    }

    /* Copy the report to the caller's buffer */
    OE_Memcpy(&args->report, &copy.report, sizeof(SGX_Report));
}
