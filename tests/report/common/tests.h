// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TESTS_H_
#define _TESTS_H_

#include <openenclave/internal/report.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/enclave.h>
#else
#include <openenclave/host.h>
#endif

#ifndef OE_BUILD_ENCLAVE

// The host side API requires the enclave to be passed in.

extern oe_enclave_t* g_enclave;

#endif

void test_local_report(sgx_target_info_t* target_info);
void test_remote_report();
void test_parse_report_negative();
void test_local_verify_report();
void test_remote_verify_report();
void test_verify_report_with_collaterals();
void test_get_signer_id_from_public_key();

#endif
