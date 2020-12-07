// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include "edl_opt_out_t.h"
#include "header_t.h"

void enc_edl_opt_out()
{
    /* logging.edl */
    OE_TEST(oe_log_ocall(0, NULL) == OE_UNSUPPORTED);

    /* ioctl.edl */
    OE_TEST(oe_syscall_ioctl_ocall(NULL, 0, 0, 0, 0, NULL) == OE_UNSUPPORTED);

    /* time.edl */
    OE_TEST(oe_syscall_nanosleep_ocall(NULL, NULL, NULL) == OE_UNSUPPORTED);

    /* unistd.edl */
    OE_TEST(oe_syscall_getpid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getppid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getpgrp_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getuid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_geteuid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getgid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getegid_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getpgid_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getgroups_ocall(NULL, 0, NULL) == OE_UNSUPPORTED);

#if __x86_64__ || _M_X64
    /* debug.edl */
    OE_TEST(
        oe_sgx_backtrace_symbols_ocall(NULL, NULL, NULL, 0, NULL, 0, NULL) ==
        OE_UNSUPPORTED);

    /* sgx/switchless.edl*/
    OE_TEST(oe_sgx_sleep_switchless_worker_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_sgx_wake_switchless_worker_ocall(NULL) == OE_UNSUPPORTED);

    /* sgx/attestation */
    {
        oe_result_t result = OE_OK;

        OE_TEST(
            oe_get_supported_attester_format_ids_ocall(
                &result, NULL, 0, NULL) == OE_UNSUPPORTED);
        OE_TEST(result == OE_UNSUPPORTED);
        result = OE_OK;
        OE_TEST(
            oe_get_supported_attester_format_ids_ocall(
                &result, NULL, 0, NULL) == OE_UNSUPPORTED);
        OE_TEST(result == OE_UNSUPPORTED);
        result = OE_OK;
        OE_TEST(
            oe_get_quote_verification_collateral_ocall(
                &result,
                NULL,
                0,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL,
                NULL,
                0,
                NULL) == OE_UNSUPPORTED);
        OE_TEST(result == OE_UNSUPPORTED);
        result = OE_OK;
        OE_TEST(
            oe_get_qetarget_info_ocall(&result, NULL, NULL, 0, NULL) ==
            OE_UNSUPPORTED);
        OE_TEST(result == OE_UNSUPPORTED);
    }
#endif
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    1);   /* NumTCS */

#define TA_UUID                                            \
    { /* 892e7f65-5da1-45d0-8209-53795ce5be8f */           \
        0x892e7f65, 0x5da1, 0x45d0,                        \
        {                                                  \
            0x82, 0x09, 0x53, 0x79, 0x5c, 0xe5, 0xbe, 0x8e \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "edl_opt_out test")
