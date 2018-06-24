#include <openenclave/enclave.h>
#include "report.h"

const void* oe_link_enclave(void)
{
    static const void* symbols[] =
    {
        oe_handle_verify_report,
    };

    return symbols;
}
