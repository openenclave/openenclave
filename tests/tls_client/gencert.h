#ifndef _GENCERT_H
#define _GENCERT_H

#include <openenclave/enclave.h>

oe_result_t oe_generate_cert_and_private_key(
    const char* common_name,
    uint8_t** cert_out,
    size_t* cert_size_out,
    uint8_t** private_key_out,
    size_t* private_key_size_out);

#endif /* _GENCERT_H */
