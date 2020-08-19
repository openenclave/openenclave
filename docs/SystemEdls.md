# Open Enclave System EDL Files

This document lists the system EDL files supported by Open Enclave. To opt-into these files, user can
use `from path/to/edl import *` syntax to import all the ecalls/ocalls defined by the file.
Alternatively, the user can use the `from path/to/edl import name_of_the_call` syntax to selectively import
the ecalls/ocalls. Refer to the [Explicit Enclave Opt-in to System OCalls document](/docs/DesignDocs/system_ocall_opt_in.md)
for more detail.

Below, we assume the path prefix as `openenclave/edl`. The path to import an EDL file becomes
`openenclave/edl/{Name}.edl`. `{Name}.edl` (e.g., `attestation.edl`) indicates that the file
is platform-agnostic while `{Platform}/{Name}.edl` (e.g., `sgx/attestation.edl`) implies that the file
is platform-specific.

## Common EDLs

### attestation.edl
Ecall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_verify_report_ecall | N/A | - |

### keys.edl
Ecall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_get_public_key_ecall | oe_get_public_key | - |
oe_get_public_key_by_policy_ecall | oe_get_public_key_by_policy | - |

### logging.edl
Ecall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_log_init_ecall | - | Required to enable in-enclave logging. |

Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_log_ocall | oe_log | - |
oe_write_ocall | N/A | Required by internal APIs/macros such as `oe_host_printf` and `OE_TEST` |

### memory.edl
Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_realloc_ocall | oe_host_realloc | _ |

## Syscall system EDLs

The section lists the EDLs that are required by an enclave to perform syscalls.
Note that the behavior of each supported syscall may be tailored to the TEEs
thus not behaving the same as the normal one.
The umbrella EDL `syscall.edl` allows users to opt-into all the supported
syscall-dependent EDLs at once.

### epoll.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_epoll_create1_ocall | epoll_create1 | - |
oe_syscall_epoll_wait_ocall | epoll_wait | - |
oe_syscall_epoll_wake_ocall | epoll_wake | - |
oe_syscall_epoll_ctl_ocall | epoll_ctl | - |
oe_syscall_epoll_close_ocall | epoll_close | - |

### fcntl.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_open_ocall | open | - |
oe_syscall_read_ocall | read | - |
oe_syscall_write_ocall | write | - |
oe_syscall_readv_ocall | readv | - |
oe_syscall_writev_ocall | writev | Required by printf/fprintf libc APIs. |
oe_syscall_lseek_ocall | lseek | - |
oe_syscall_pread_ocall | pread | - |
oe_syscall_pwrite_ocall | pwrite | - |
oe_syscall_close_ocall | close | - |
oe_syscall_flock_ocall | flock | - |
oe_syscall_fsync_ocall | fsync | - |
oe_syscall_fdatasync_ocall | fdatasync | - |
oe_syscall_dup_ocall | dup | Required by performing I/O via console. |
oe_syscall_opendir_ocall | opendir | - |
oe_syscall_readdir_ocall | readdir | - |
oe_syscall_rewinddir_ocall | rewinddir | - |
oe_syscall_closedir_ocall | closedir | - |
oe_syscall_stat_ocall | stat | - |
oe_syscall_fstat_ocall | fstat | - |
oe_syscall_access_ocall | access | - |
oe_syscall_link_ocall | link | - |
oe_syscall_unlink_ocall | unlink | - |
oe_syscall_rename_ocall | rename | - |
oe_syscall_truncate_ocall | truncate | - |
oe_syscall_mkdir_ocall | mkdir | - |
oe_syscall_rmdir_ocall | rmdir | - |
oe_syscall_fcntl_ocall | fcntl | - |

### ioctl.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_ioctl_ocall | ioctl | - |

### poll.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_poll_ocall | poll | - |

### signal.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_kill_ocall | kill | - |

### socket.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_close_socket_ocall | close | - |
oe_syscall_socket_ocall | socket | - |
oe_syscall_shutdown_sockets_device_ocall | N/A | - |
oe_syscall_socketpair_ocall | socketpair | - |
oe_syscall_connect_ocall | connect | - |
oe_syscall_accept_ocall | accept | - |
oe_syscall_bind_ocall | bind | - |
oe_syscall_listen_ocall | listen | - |
oe_syscall_recvmsg_ocall | recvmsg | - |
oe_syscall_sendmsg_ocall | sendmsg | - |
oe_syscall_recv_ocall | recv | - |
oe_syscall_recvfrom_ocall | recvfrom | - |
oe_syscall_send_ocall | send | - |
oe_syscall_sendto_ocall | sendto | - |
oe_syscall_recvv_ocall | readv | - |
oe_syscall_sendv_ocall | writev | - |
oe_syscall_shutdown_ocall | shutdown | - |
oe_syscall_setsockopt_ocall | setsockopt | - |
oe_syscall_getsockopt_ocall | getsockopt | - |
oe_syscall_getsockname_ocall | getsockname | - |
oe_syscall_getpeername_ocall | getpeername | - |
oe_syscall_getaddrinfo_open_ocall | N/A | Used by internal APIs to get `addrinfo` |
oe_syscall_getaddrinfo_read_ocall | N/A | Used by internal APIs to get `addrinfo` |
oe_syscall_getaddrinfo_close_ocall | N/A | Used by internal APIs to get `addrinfo` |
oe_syscall_getnameinfo_ocall | N/A | Used by internal APIs to resolve `addrinfo` |

### time.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_nanosleep_ocall | nanosleep | - |

### unistd.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_getpid_ocall | getpid | - |
oe_syscall_getppid_ocall | getppid | - |
oe_syscall_getpgrp_ocall | getpgrp | - |
oe_syscall_getuid_ocall | getuid | - |
oe_syscall_geteuid_ocall | geteuid | - |
oe_syscall_getgid_ocall | getgid | - |
oe_syscall_getegid_ocall | getegid | - |
oe_syscall_getpgid_ocall | getpgid | - |
oe_syscall_getgroups_ocall | getgroups | - |

### utsname.edl
Ocall | Dependent syscall | Comments |
:---|:---:|:---|
oe_syscall_uname_ocall | uname | - |

## SGX-specific system EDLs

The section lists the SGX-specific system EDLs.
The umbrella EDL `sgx/platform.edl` allows users to opt-into all the EDLs at once.

### sgx/attestation.edl
Ecall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_get_sgx_report_ecall | N/A | - |
oe_get_report_v2_ecall | oe_get_report_v2 | Depend on other ocalls in the edl file. |
oe_verify_local_report_ecall | oe_verify_report | - |

Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_get_supported_attester_format_ids_ocall | oe_attester_initialize (experimental) | Used by internal APIs. |
oe_get_qetarget_info_ocall | oe_attester_initialize (experimental) | Used by internal APIs. |
oe_get_quote_ocall | oe_attester_initialize (experimental) | Used by internal APIs. |
oe_get_quote_verification_collateral_ocall | oe_attester_initialize (experimental) | Used by internal APIs. |

## sgx/cpu.edl
Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_sgx_get_cpuid_table_ocall | N/A | Required by enclave initialization. |

## sgx/debug.edl
Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_sgx_backtrace_symbols_ocall | backtrace, backtrace_symbols | Part of libc APIs. |

## sgx/switchless/edl
Ecall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_sgx_init_context_switchless_ecall | N/A | Required by the switchless call feature. |
oe_sgx_switchless_enclave_worker_thread_ecall | N/A | Required by the switchless call feature. |

Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_sgx_wake_switchless_worker_ocall | N/A | Required by the switchless call feature. |
oe_sgx_sleep_switchless_worker_ocall | N/A | Required by the switchless call feature. |

## sgx/thread.edl
Ocall | Dependent Public APIs | Comments |
:---|:---:|:---|
oe_sgx_thread_wake_wait_ocall | N/A | Required by the threading feature. |

## OP-TEE-specific system EDLs

The umbrella EDL `optee/platform.edl` allows users to opt-into all the
necessary EDLs for OP-TEE at once. Currently, it only includes `memory.edl`
