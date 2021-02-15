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

    /* epoll.edl */
    OE_TEST(oe_syscall_epoll_create1_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_epoll_wait_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_epoll_wake_ocall(NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_epoll_ctl_ocall(NULL, 0, 0, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_epoll_close_ocall(NULL, 0) == OE_UNSUPPORTED);

    /* fcntl.edl */
    OE_TEST(oe_syscall_read_ocall(NULL, 0, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_write_ocall(NULL, 0, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_pread_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_pwrite_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_fsync_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_fdatasync_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_opendir_ocall(NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_readdir_ocall(NULL, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_rewinddir_ocall(0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_closedir_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_stat_ocall(NULL, NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_fstat_ocall(NULL, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_access_ocall(NULL, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_link_ocall(NULL, NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_unlink_ocall(NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_rename_ocall(NULL, NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_truncate_ocall(NULL, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_mkdir_ocall(NULL, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_rmdir_ocall(NULL, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_fcntl_ocall(NULL, 0, 0, 0, 0, NULL) == OE_UNSUPPORTED);

    /* ioctl.edl */
    OE_TEST(oe_syscall_ioctl_ocall(NULL, 0, 0, 0, 0, NULL) == OE_UNSUPPORTED);

    /* signal.edl */
    OE_TEST(oe_syscall_kill_ocall(NULL, 0, 0) == OE_UNSUPPORTED);

    /* socket.edl */
    OE_TEST(oe_syscall_close_socket_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_socket_ocall(NULL, 0, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_shutdown_sockets_device_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_socketpair_ocall(NULL, 0, 0, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_connect_ocall(NULL, 0, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_accept_ocall(NULL, 0, NULL, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_bind_ocall(NULL, 0, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_listen_ocall(NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_recvmsg_ocall(
            NULL, 0, NULL, 0, NULL, NULL, 0, 0, NULL, 0, NULL, 0) ==
        OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_sendmsg_ocall(NULL, 0, NULL, 0, NULL, 0, 0, NULL, 0, 0) ==
        OE_UNSUPPORTED);
    OE_TEST(oe_syscall_recv_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_recvfrom_ocall(NULL, 0, NULL, 0, 0, NULL, 0, NULL) ==
        OE_UNSUPPORTED);
    OE_TEST(oe_syscall_send_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_sendto_ocall(NULL, 0, NULL, 0, 0, NULL, 0) ==
        OE_UNSUPPORTED);
    OE_TEST(oe_syscall_recvv_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_sendv_ocall(NULL, 0, NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(oe_syscall_shutdown_ocall(NULL, 0, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_setsockopt_ocall(NULL, 0, 0, 0, NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_getsockname_ocall(NULL, 0, NULL, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_getpeername_ocall(NULL, 0, NULL, 0, NULL) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_getaddrinfo_open_ocall(NULL, NULL, NULL, NULL, NULL) ==
        OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_getaddrinfo_read_ocall(
            NULL, 0, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL) ==
        OE_UNSUPPORTED);
    OE_TEST(oe_syscall_getaddrinfo_close_ocall(NULL, 0) == OE_UNSUPPORTED);
    OE_TEST(
        oe_syscall_getnameinfo_ocall(NULL, NULL, 0, NULL, 0, NULL, 0, 0) ==
        OE_UNSUPPORTED);

    /* poll.edl */
    OE_TEST(oe_syscall_poll_ocall(NULL, NULL, 0, 0) == OE_UNSUPPORTED);

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

    /* utsname.edl */
    OE_TEST(oe_syscall_uname_ocall(NULL, NULL) == OE_UNSUPPORTED);

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
