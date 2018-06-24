#include <openenclave/enclave.h>
#include "report.h"

//
// main.S (the compilation unit containing the entry point) contains a
// reference to this function, which sets up a dependency chain from the
// object file containing the entry point to all symbols referenced in
// the array below (as well as symbols reachable from those symbols).
// This forces the collection of symbols to be included in the enclave
// image so that the linker will consider them when resolving symbols in
// subsequently linked libraries. The original purpose of this method was
// to make oe_handle_verify_report() accessible to the oeenclave library.
//
const void* oe_link_enclave(void)
{
    static const void* symbols[] = {
        oe_handle_verify_report,
    };

    return symbols;
}
