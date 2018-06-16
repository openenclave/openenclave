#include "report.h"

// This function overrides the weak version defined in liboecore. When the
// enclave appliation is linked with liboeenclave, then liboecore calls
// this function to initialize the liboeenclave library. Otherwise, liboecore
// calls its own weak version.
void __liboeenclave_init(void)
{
    // Register the verify report ECALL:
    oe_register_verify_report();
}
