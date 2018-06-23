#include <openenclave/enclave.h>
#include "report.h"

void* oe_link_enclave(void)
{
    return oe_handle_verify_report;
}
