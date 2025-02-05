Changelog
=========

Major work such as new features, bug fixes, feature deprecations, and other
breaking changes should be noted here. It should be more concise than `git log`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased][Unreleased_log]
--------------
### Security
- Updated mbedtls from version 2.28.1 to 2.28.9

### Added
- (#4832) OE SDK now accepts environment variable `OE_INTEL_QVL_LOAD_POLICY`, which can be used to specify the policy for loading [Intel DCAP's QvE](https://github.com/intel/SGXDataCenterAttestationPrimitives) (Quote Verification) for SGX/TDX quote verification. The value can be one of the following:
  - `SGX_QL_EPHEMERAL` and `SGX_QL_DEFAULT` - Default policy. QvE is initialized and terminated on every quote verification function call.
  - `SGX_QL_PERSISTENT` - All the threads will share single QvE instance, and QvE is initialized on first use and reused until process ends.
  - `SGX_QL_EPHEMERAL_QVE_MULTI_THREAD` - QvE is loaded per thread and be unloaded before function exit.
  - `SGX_QL_PERSISTENT_QVE_MULTI_THREAD` - QvE is loaded per thread and only be unloaded before thread exit.

[v0.19.0][v0.19.0_log]
--------------
### Added

- OE SDK can now be built with Clang-11 and it is recommended to upgrade the compiler to Clang-11 if you are building the SDK from source. Building with Clang-10 is still supported until the next Clang upgrade, but is not recommended.
  - Building OE SDK now includes the following LVI mitigation options:
    - `ControlFlow-GNU` - enables LVI mitigation using the existing GNU-based mitigation specified by `LVI_MITIGATION_BINDIR`. This option is recommended when building OE SDK with Clang-10.
    - `ControlFlow-Clang` - enables Clang-based LVI mitigations. Choosing this option requires Clang-11.
    - `ControlFlow` - enables LVI mitigation but default to the recommended method, which is currently ControlFlow-GNU.
    - `None` - no LVI mitigations are enabled.

- Added a TDX verifier plugin based on Intel QVL/QvE
  - Added two public APIs to initialize and shut down
    the plugin defined in the `openenclave/attestation/tdx/evidence.h`
    - `oe_tdx_verifier_initialize()`
    - `oe_tdx_verifier_shutdown()`
  - Added a new format uuid for TDX quote `OE_FORMAT_UUID_TDX_QUOTE_ECDSA`
  - Added a new OCALL `oe_verify_tdx_quote_ocall` that is
    used by the plugin internally (see `openenclave/edl/sgx/tdx_verification.edl`)
  - Steps for verify a TDX quote
    1. Initialize the plugin via `oe_tdx_verifier_initialize`
    2. Invoke `oe_verify_evidence` by specifying the quote and
      format id as `OE_FORMAT_UUID_TDX_QUOTE_ECDSA`
    3. Parse the claims (refer the definitions of TDX claims
       to `openenclave/attestation/evidence.h`)
  - Note that the `oe_verify_evidence` with the plugin currently
    does not support input endorsements (must be `NULL`)

- Added two APIs `oe_get_tdx_endorsements` and `oe_free_tdx_endorsements` to fetch
  and free the endorsements for the given TDX quote. The APIs are for users who want
  to manage (e.g., caching) the endorsements by themselves instead of relying on the
  existing caching mechanisms (e.g., supported by DCAP).
  See `openenclave/attestation/tdx/evidence.h` for more detail of the APIs.

- Added support for V4 collateral from Intel for SGX and TDX

### Changed
- snmalloc (0.6.0) now only requires 16KiB initially per thread, compared to 256 KiB previously (0.5.3). Thread-local heaps only grow by a constant amount until the next power of 2, eg. 16KiB, 16KiB, 32KiB, 64KiB, ... 1MiB, 2MiB, 2MiB, ..., as opposed to a fixed amount previously (256 KiB). Allocator metadata is kept separately, making corruption attacks less likely. There are some applications for which this update in snmalloc will result in an increase in EPC memory as specified in the enclave configuration file.


[v0.18.5][v0.18.5_log]
--------------
### Security
- Updated OpenSSL used inside the enclave to v1.1.1t. See [OpenSSL's release notes](https://www.openssl.org/news/openssl-1.1.1-notes.html) for more details


[v0.18.3][v0.18.3_log]
--------------
### Added
-  Added oe_set_host_log_level and oe_set_enclave_log_level APIs to dynamically modify host and enclave log level verbosity, respectively. See #4610 for more details
- Added backtrace debug log for unhandled exceptions if the enclave is configured with and CapturePFGPExceptions=1, the backtrace information will be printed in the enclave log when an in-enclave exception is not handled by trusted handlers. If the enclave is not configured with CapturePFGPExceptions=1, the similar helper message in the following will be printed in the log: `2022-07-13T00:25:05+0000.276579Z 
 (H)ERROR] tid(0x7f6cbb2b1f40) | Unhandled in-enclave exception. To get more information, configure the enclave with CapturePFGPExceptions=1 and enable the in-enclave logging.`

### Changed
- Fixed bugs in oe_validate_revocation_list regarding PCCS API v3.0
-  Fixed issue where oe_hex_dump prints data to stdout, even when logging callback is set
- Fixed the issue where enclave stack was not showing up in ocall callstack in Windows debuggers. Added padding to restore offset of callsites field to previous value.

### Security
- Updated OpenSSL used inside the enclave to v1.1.1q. See [OpenSSL's release notes](https://www.openssl.org/news/openssl-1.1.1-notes.html) for more details
- Update Mbed-TLS used inside the enclave to 2.28.1. See [Mbed-TLS's release notes](https://github.com/Mbed-TLS/mbedtls/releases/tag/v2.28.1) for more details.


[v0.18.2][v0.18.2_log]
--------------
### Changed
- Fixed the incorrect behavior of pthread_mutex_init() and std::mutex such that they no longer create a recursive lock by default. Please see issue #4555 for more details.

### Security
- Mitigated CVE-2022-21233. Please refer to the [security advisory](https://github.com/openenclave/openenclave/security/advisories/GHSA-v3vm-9h66-wm76) for the same.
        - The mitigations require an extra copy for ocalls in oeedger8r generated code.
        - If you are running on a processor that is not affected by the CVE, you can turn off oeedger8r introduced mitigations by defining a global C variable `bool oe_edger8r_secure_unserialize = false;` in enclave side code.


### Deprecated
- Ubuntu 18.04 has reached end of support, and will no longer be supported.

[v0.18.1][v0.18.1_log]
--------------
### Changed
- Calling oe_log from an enclave resulted in partial log output. #4547 fixed this.
- Fixed #4540. The fix **does not** introduce functional changes, but updates `memcpy_with_barrier` such that the source address will be always aligned when the function does 2- or 4-byte memory write.
- Fixed #4542. The issue affects only those applications that ignore `SIGHUP`, `SIGALRM`, `SIGPIPE`, `SIGPOLL`, `SIGUSR1`, or`SIGUSR2` using `signal(signum, SIG_IGN)` on Linux. The issue has **no impact** on the enclave runtime.


[v0.18.0][v0.18.0_log]
--------------
### Added
- `oeapkman` is a Linux tool for installing and using Alpine Linux static libraries within enclaves.
  - The command `oeapkman add package` can be used to install the specified package.
    Typically `-static` and `-dev` (e.g.: sqlite-static, sqlite-dev) packages need to be installed.
  - The command `oeapkman root` prints out the path to the Alpine Linux distribution maintained by `oeapkman`.
    The root path is useful for providing paths to header files and static libraries to the compiler and linker respectively.
  - The command `oeapkman exec` can be used to execute commands within the Alpine Linux environment.
    For example, after executing `oeapkman add clang build-base cmake` to install development tools,
	running `oeapkman exec clang -c file.c` would compile `file.c` in current folder using the clang compiler that
	has been installed in the Alpine Linux environment. `oeapkman exec bash` would launch a bash shell in the current folder.
  - The `--optee` prefix can be applied to the commands to target OP-TEE.
    `oeapkman --optee add sqlite-static` installs aarch64 sqlite static library.
	`oeapkman --optee exec gcc -c file.c` cross-compile `file.c` to target OP-TEE.
  - See [samples/apkman](samples/apkman) for a complete example demonstrating use of the `sqlite` database library within enclaves.
- Support for `compiler-rt`. `oelibc` includes LLVM's `compiler-rt-10.0.1`.
- Update logging function setup API name for SGX Quote Provider plugin to `sgx_ql_set_logging_callback` and mark API name `sgx_ql_set_logging_function` as deprecated.
- Add new policy type `OE_POLICY_ENDORSEMENTS_BASELINE` for `oe_verify_evidence` API to pass additional parameters to QVL for more advanced quote validation.
- The CapturePFGPExceptions preference is now supported in SGX1 debug mode on Linux.
  - When setting CapturePFGPExceptions=1, OE will simulate all the SIGSEGV as #PF by forwarding the host information (faulting address) to in-enclave exception handlers.
  - Note that this feature is for debug only and there is no guarantee that the simulated behavior works the same as the hardware feature in SGX2.
- Added the support of using vDSO interfaces for SGX enclaves on Linux to enable synchronous exception handling. The `oehost` library automatically opts into the vDSO interface when it is available (Linux kernel 5.11+).

## Changed
- Updated libcxx to version 10.0.1
- Updated the mbedTLS from 2.16 LTS to 2.28 LTS
- Updated the SymCrypt-OpenSSL to v1.1.0
- Updated the support of the SymCrypt module to v101.3.0

### Security
- Updated openssl to version 1.1.1o. Please refer to [release notes](https://www.openssl.org/news/openssl-1.1.1-notes.html) to find CVEs addressed by this version.

[v0.17.7][v0.17.7_log]
-------------
### Changed
- Increased the value of maximum TCS from 32 to 1000, allowing SGX applications to create more threads.

### Security
- Updated openssl to version 1.1.1n. Please refer to [release notes](https://www.openssl.org/news/openssl-1.1.1-notes.html) to find CVEs addressed by this version.

[v0.17.6][v0.17.6_log]
--------------

### Added
- Added support FIPS-enabled OpenSSL based on [SymCrypt](https://github.com/Microsoft/SymCrypt).
  - Add a new library `oesymcryptengine`, which is a customized build of [SymCrypt OpenSSL engine](https://github.com/Microsoft/SymCrypt-OpenSSL).
  - To use FIPS-enabled OpenSSL with SymCrypt, users need to link their enclave against
    both `oesymcryptengine` and `libsymcrypt.so` (part of [SymCrypt](https://github.com/Microsoft/SymCrypt) release packages) in addition to OpenSSL libraries, and include `entropy.edl` in the edl file. Note that `libsymcrypt.so` needs to be placed under the same directory with the enclave binary.
  - See the [attested_tls sample](samples/attested_tls#build-and-run) for an example of building enclaves with FIPS-enabled OpenSSL based on SymCrypt (set `OE_CRYPTO_LIB` to `openssl_symcrypt_fips`).
- Added support for POSIX mmap and munmap.
- Enabled MUSL conf functions.
- Added callback option to capture and modify enclave logs.

### Security
- Update mbedTLS to version 2.16.12. Refer to the [2.16.12](https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.12) release notes for the set of issues addressed.
- Note: 2.16 LTS is at End Of Life. mbedTLS libs included with the Open Enclave SDK will move to use the 2.28 LTS branch in the next release. 2.28.0 has certain breaking changes. To understand how these changes will impact your application, please refer to the release notes for [2.28.0](https://github.com/ARMmbed/mbedtls/releases/tag/v2.28.0).

[v0.17.5][v0.17.5_log]
--------------

### Added 
- Added MUSL time functions
asctime, asctime_r, ctime, ctime_r, ftime, localtime, localtime_r, strptime, timespec_get, wcsftime.

### Changed
- Fixed bug with incorrect layout of thread-local sections (tbss and tdata). Previous releases of OE had a bug where these sections
will be laid out incorrectly in some cases where the tbss section had a lower alignment value than tdata section.
- OpenSSL is now built with threads support (with the dependency on the host). Note that the previous versions of OpenSSL are not suitable for multi-threaded applications.

### Security
- Updated openssl to version 1.1.1l. Please refer to release log to find list of CVEs addressed by this version.


[v0.17.2][v0.17.2_log]
--------------

### Security
- Updated openssl to version 1.1.1l. Please refer to release log to find list of CVEs addressed by this version.


[v0.17.1][v0.17.1_log]
--------------

### Added
- Enabled creation of enclaves with base address 0x0 in SGX on Linux.
  - This feature requires PSW version 2.14.1 or above.
  - In 0-base enclaves a page fault is thrown on NULL pointer dereference.
  - This enables applications to adopt NullPointerException/ NullReferenceException in their program logic and/or use other application stacks that do (Example, .NET runtime).
  - Developers can create an 0-base enclave by setting the oesign tool configuration option 'CreateZeroBaseEnclave' to 1 or by passing in argument CREATE_ZERO_BASE_ENCLAVE=1 in OE_SET_ENCLAVE_SGX2().
  - If the 0-base enclave creation is chosen, enclave image start address should be provided by setting the oesign tool configuration option 'StartAddress' or pass in the argument ENCLAVE_START_ADDRESS in OE_SET_ENCLAVE_SGX2().

### Security
- Fix [CVE-2021-33767](https://github.com/openenclave/openenclave/security/advisories/GHSA-mj87-466f-jq42)

[v0.17.0][v0.17.0_log]
--------------

### Added
- Ubuntu 20.04 packages are included in this release.
- OE SDK is now built using clang-10. It is required to upgrade the compiler to clang-10 if you are building the SDK from source.
- Add the CapturePFGPExceptions preference for the SGX2 feature of capturing #PF and #GP exceptions inside an enclave.
  - Developers can specify the CapturePFGPExceptions with a binary value in the enclave config file or set the value via the newly added OE_SET_ENCLAVE_SGX2 macro, which is used to set SGX2-specific properties.
  - When setting CapturePFGPExceptions=1, the OE loader will enable the feature when running on an SGX2-capable CPU.
  - Once enabled, the in-enclave exception handler can capture the #PF (with the OE_EXCEPTION_PAGE_FAULT code) and #GP (with the code OE_EXCEPTION_ACCESS_VIOLATION code) exceptions.
  - More information about the exceptions can be found in the `faulting_address` and `error_code` members of the `oe_exception_record_t` structure passed into the handler.
- Add the following attestation claims from oe_verify_evidence():
  - OE_CLAIM_TCB_STATUS
  - OE_CLAIM_TCB_DATE
- Publish tool `oeutil`.
  - The tool, currently under the tools directory, will [integrate multiple OE utilities](tools/oeutil/README.md) in the future.
  - The tool integrated `oegenerate` in this release.
- SGX enclaves created using OE SDK can now be debugged using `oelldb`.
  `oelldb` is a python based extension for LLDB that supports debugging SGX enclaves. lldb-7 or above is required.
- SGX Evidence verification stops checking SGX QEIdentity nextUpdate field.

### Deprecated
- The `Release` build type for building the Open Enclave SDK from source is deprecated. The recommendation is using `RelWithDebInfo` instead.

[v0.16.1][v0.16.1_log]
--------------
### Added
- Add the support for SGX quote verification collateral version 3 with the CRL in DER format by default. Refer to [Get Quote Verification Collateral](https://download.01.org/intel-sgx/sgx-dcap/1.10/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf) section 3.3.1.5.

[v0.16.0][v0.16.0_log]
--------------
### Added
- Add the initial support of cryptographic module loading in SGX enclaves. Refer to the [design document](docs/DesignDocs/CryptoModuleLoadingSupport.md) for more detail.
- Add the support of getrandom libc API and syscall in enclaves.
- Add `libsgx-quote-ex`, `sgx-aesm-service` and several SGX AESM plugins to Ansible scripts so that users will be able to select in-process or out-of-process call path for quote generation. Refer to the [attestation sample](samples/attestation/README.md#determining-call-path-for-sgx-quote-generation) for more information.
- Open Enclave SDK installation on Linux sets the environment variable "SGX_AESM_ADDR" to 1 to enable attestation quote generation to occur out of the application process.
- Add the support of the OE_ENCLAVE_FLAG_DEBUG_AUTO flag to the oe_create_enclave API. When the flag is set and the OE_ENCLAVE_FLAG_DEBUG flag is cleared, the debug mode is automatically turned on/off based on the value of Debug specified in the enclave config file.
- Publish test tool `oegenerate`.
  - The tool, currently under the tools directory, was originally named oecert under the tests/tools directory.
  - The tool can be used to generate certificates, reports, and evidence in various formats.
  - The tool is for debugging purposes and is not suitable for production use.
- Full support for SGX KSS (Key Separation and Sharing) including
  - FamilyID and ExtendedProductionID in enclave configuration file. Refer to [Build and Sign an Enclave](docs/GettingStartedDocs/buildandsign.md) for more information.
  - config_id and config_svn at enclave loading time. Refer to [Open Enclave Init-time Configuration Interface](docs/DesignDocs/InitTimeConfigurationInterface.md) for more information.

### Changed
- The OpenEnclave CMake configuration now explicitly sets CMAKE_SKIP_RPATH to TRUE. This change should not affect fully static-linked enclaves.
- oe_verify_attestation_certificate_with_evidence() has been considered insufficient for security and deprecated, because it does not allow users to pass in optional endorsements and policies. Use the new, experimental oe_verify_attestation_certificate_with_evidence_v2() instead to generate a self-signed certificate for use in the TLS handshaking process.
  - Refer to the [issue](https://github.com/openenclave/openenclave/issues/3820) and the [proposed attestation API requirements](docs/DesignDocs/AttestationApiRequirements.md) for more details.
- In/out parameters in EDL now have the default count equals to one if the `count` attribute is not used.
- Improved attestation evidence verification performance.
- Open Enclave SDK will be built with clang-10 starting v0.17.0 release. We had originally planned to upgrade to clang-10 in the v0.16.0 release, but ran into some issues. We recommend that developers move to clang-10 starting v0.17.0 release.

### Security
- Update MUSL to version 1.2.2. Refer to MUSL release notes between version 1.1.22 to 1.2.2 for the set of issues addressed.

[v0.15.0][v0.15.0_log]
--------------
### Added
- Oeedger8r now supports the warning flag -W<option>. The available options include:
  - -Wreturn-ptr: Check if an OCALL or ECALL returns a pointer.
  - -Wptr-in-struct: Check if a user-defined struct includes a un-annotated pointer member.
  - -Wforeign-type-ptr: Check if an OCALL or ECALL includes a parameter that is the pointer of a foreign type.
  - -Wptr-in-function: Check if an OCALL or ECALL includes a un-annotated pointer argument.
  - -Wall: Enable all the warning options.
  - -Wno-<option>: Disable the corresponding warning.
  - -Werror: Turn warnings into errors.
  - -Werror=<option>: Turn the specified warning into an error.
- oesign sign now allows option -o/--output-file, to specify location to write signature of enclave image.
- Debugger Contract has been extended to support multiple modules.
  - Refer to [design document](docs/DesignDocs/DebuggerSupportForMultiModuleEnclaves.md) for details.

### Changed
- oe_get_attestation_certificate_with_evidence() has been considered insufficient for security and deprecated, because it does not allow users to pass in a provided nonce or additional customized information. Use the new, experimental oe_get_attestation_certificate_with_evidence_v2() instead to generate a self-signed certificate for use in the TLS handshaking process.
  - Refer to the [issue](https://github.com/openenclave/openenclave/issues/3820) and the [proposed attestation API requirements](docs/DesignDocs/AttestationApiRequirements.md#getevidence-call) for more details.
- Debugger Contract
  - `path` fields in `oe_debug_enclave_t` and `oe_debug_module_t` are now defined to be in
    UTF-8 encoding. Previously the encoding was undefined. To ensure smooth transition, debuggers
	are required to try out both UTF-8 as well as the previous encoding and pick the one that works.

### Security
- Update mbedTLS to version 2.16.10. Refer to the [2.16.10](https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.10) and [2.16.9](https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.9) release notes for the set of issues addressed.

- OPENSSL is updated to version 1.1.1k.

[v0.14.0][v0.14.0_log]
--------------

### Added
- Add the deep-copy out parameter support as an experimental, SGX-only feature. To use the feature, pass `--experimental` when invoking oeedger8r. Refer to the [design document](docs/DesignDocs/DeepCopyOutParameters.md) for more detail.

### Changed
- OE SDK is now built using clang-8. It is required to upgrade the compile to clang-8 if you are building the SDK from source.

### Deprecated
- The support of building the SDK for Intel SGX with GCC from source is no longer supported. The recommended compiler is Clang.


[v0.13.0][v0.13.0_log]
--------------

### Added
- OpenSSL version 1.1.1 libraries are now available for an enclave to use. See the [attested_tls sample](samples/attested_tls#build-and-run) for an example of building enclaves with OpenSSL.
- Enabled oe_verify_evidence() with a NULL format id to verify the legacy report generated by oe_get_report().
- Added the following SGX attestation claims from oe_verify_evidence():
     - OE_CLAIM_SGX_PF_GP_EXINFO_ENABLED
     - OE_CLAIM_SGX_ISV_EXTENDED_PRODUCT_ID
     - OE_CLAIM_SGX_IS_MODE64BIT
     - OE_CLAIM_SGX_HAS_PROVISION_KEY
     - OE_CLAIM_SGX_HAS_EINITTOKEN_KEY
     - OE_CLAIM_SGX_USES_KSS
     - OE_CLAIM_SGX_CONFIG_ID
     - OE_CLAIM_SGX_CONFIG_SVN
     - OE_CLAIM_SGX_ISV_FAMILY_ID
- Added the following fields for SGX KSS (Key Separation and Sharing) support:
     - FamilyID
     - ExtendedProductID

## Breaking Changes
- liboecryptombed is now called liboecryptombedtls and will no longer be automatically included as a link dependency when linking liboeenclave in CMake.
     - The `openenclave-config.cmake` and `openenclave-lvi-mitigation-config.cmake` will not specify the renamed liboecryptombedtls as a `PUBLIC` link requirement for liboeenclave.
     - Enclave apps that are built with CMake and use the Open Enclave's CMake configurations must now explicitly include OE crypto wrapper library when linking `openenclave::oeenclave`.
     - See the [CMakeLists.txt in the helloworld sample](samples/helloworld/enclave/CMakeLists.txt#L32) for an example. Here `OE_CRYPTO_LIB` is set to `mbedtls` in [parent CMakeList file](samples/helloworld/CMakeLists.txt#L22).
     - Enclave apps that are built with Make and rely on Open Enclave's pkgconfig must now explicitly include OE crypto wrapper library in linker dependency flags.
     - See the [Makefile in the helloworld sample](samples/helloworld/enclave/Makefile#L34) for an example. Here `OE_CRYPTO_LIB` is set to `mbedtls` in [parent MakeList file](samples/helloworld/Makefile#L9).

### Changed
- Syscalls are internally dispatched directly to their implementation functions instead of via a switch-case.
  This allows the linker to eliminate unused syscalls, leading to slightly reduced TCB.
  The command `objdump -t enclave-filename | grep oe_SYS_` can be used to figure out the list of syscalls invoked by
  code within the enclave. While most syscall implementations make OCALLs, some may be implemented entirely within
  the enclave or may be noops (e.g SYS_futex).
- Changed the attestation evidence extension OIDs for certificates generated by the following APIs. Verifiers must call oe_verify_attestation_certificate APIs from v.0.11.0 or above.
     - oe_generate_attestation_certificate(): "1.3.6.1.4.1.311.105.1"
     - oe_get_attestation_certificate_with_evidnece(): "1.3.6.1.4.1.311.105.2"

[v0.12.0][v0.12.0_log]
--------------

### Added
- Initial implementation of the [Malloc Info API](docs/DesignDocs/Mallinfo.md) for dlmalloc (default allocator), and snmalloc.
- Added missing attribute validations to oeedger8r C++ implementation.
- Added new API *oe_log_message*.  See [design doc](docs/DesignDocs/oe_log_message()_callback_proposal.md) and [sample](samples/log_callback/README.md).
- Added APIs and a library for developers to detect leaks in enclaves. See [design doc](docs/DesignDocs/Enabledebugmalloc.md) and [sample](samples/debugmalloc/README.md).
- Added support of QVL/QVE based SGX evidence verification, as described in [design doc](docs/DesignDocs/SGX_QuoteVerify_Integration.md).
- Added a new oeverify tool that subsumes the existing host_verify sample which was installed as part of the host verify package.
It is basically the same utility as host_verify with added flexibility to pass a custom format for the evidence to be verified.

### Changed
- Fixed https://github.com/openenclave/openenclave/issues/3543, updated openenclaverc file and documents on Windows to avoid overwriting CMAKE_PREFIX_PATH.
- The local and remote attestation samples are merged into a [single sample](samples/attestation/README.md).
- Disabled a set of OpenSSL APIs/macros that are considered as unsafe based on OE's threat model.
 More specifically, those APIs allow users to configure an OpenSSL application to read certificates from the host filesystem, which is not trusted, and therefore not recommended for use in enclaves. [OpenSSLSupport.md](docs/OpenSSLSupport.md) has been updated to reflect the changes.

### Deprecated

- The Open Enclave SDK will be dropping support for Ubuntu 16.04 after Dec 2020.
Developers and partners using Ubuntu 16.04 will need to move to using Ubuntu 18.04 by then.
https://github.com/openenclave/openenclave/issues/3625 tracks this.

- The Open Enclave SDK will be dropping support for WS2016 after Dec 2020.
Developers and partners using WS2016 will need to move to using WS2019 by then.
https://github.com/openenclave/openenclave/issues/3539 tracks this.

- The Open Enclave SDK is deprecating support for gcc while *building the SDK from source* after Dec 2020.
The recommended compiler while building the SDK from source is Clang.
https://github.com/openenclave/openenclave/issues/3555 tracks this.

### Security
- Security fixes in oeedger8r
     - Fix TOCTOU vulnerability in NULL terminator checks for ocall in/out string parameters.
     - Count/size properties in deep-copied in/out structs are treated as read-only to prevent the host
	   from changing corrupting enclave memory by changing these properties.
- Fixed [Socket syscalls can leak enclave memory contents](https://github.com/openenclave/openenclave/security/advisories/GHSA-525h-wxcc-f66m) (CVE-2020-15224).

[v0.11.0][v0.11.0_log]
--------------

### Added
- Open Enclave SDK release packages can now be built on non-SGX and non-FLC machines.
- Support for arbitrarily large thread-local data for SGX machines.
- Experimental support for OpenSSL inside enclaves has been added while building the SDK from source.
     - Use BUILD_OPENSSL flag while compiling the SDK.
     - [OpenSSLSupport.md](docs/OpenSSLSupport.md) documents supported options and configuration needed to use OpenSSL inside an enclave.
- Custom claims buffer serialization/de-serialization helper functions.
- oe_verify_evidence() and oe_verify_attestation_certificate_with_evidence() have been added to the host-verify package.
- SGX attestation endorsement claims from oe_verify_evidence() will contain the following:
     - OE_CLAIM_SGX_TCB_INFO
     - OE_CLAIM_SGX_TCB_ISSUER_CHAIN
     - OE_CLAIM_SGX_PCK_CRL
     - OE_CLAIM_SGX_ROOT_CA_CRL
     - OE_CLAIM_SGX_CRL_ISSUER_CHAIN
     - OE_CLAIM_SGX_QE_ID_INFO
     - OE_CLAIM_SGX_QE_ID_ISSUER_CHAIN
- The attestation functions in local_attestation/remote_attestation/attested_tls/host_verify samples now use attestation plugin APIs, defined in attestation/attester.h and attestation/verifier.h to generate and verify evidence.
- oe_get_evidence() support for generation of SGX EPID evidences, in formats OE_FORMAT_UUID_SGX_EPID_LINKABLE and OE_FORMAT_UUID_SGX_EPID_UNLINKABLE.

### Changed
- Rename the custom claims buffer added by oe_get_evidence from "custom_claims" to "custom_claims_buffer". Likewise, replace the `OE_CLAIM_CUSTOM_CLAIMS` definition for this name with `OE_CLAIM_CUSTOM_CLAIMS_BUFFER`.
- Building SDK from source
      - HAS_QUOTE_PROVIDER cmake option has been removed. This is a continuation of the work in the previous release to allow the same build of OE SDK to run on both FLC and non-FLC machines.
      - Intel SGX EnclaveCommonAPI packages are no longer needed to build the SDK.
- oe_verify_attestation_certificate_with_evidence() can now verify certificates generated by oe_generate_attestation_certificate() as well as oe_get_attestation_certificate_with_evidence().
- The SGX attestation evidence internal structure has changed. The current structure (version 3) is not compatible with the previous version. Evidence/certificates generated prior to v0.11.0 cannot be verified by v0.11.0 verifiers. Applications that call the following experimental APIs must link to OE SDK v0.11.0 or above:
    - oe_get_evidence()
    - oe_verify_evidence()
    - oe_get_attestation_certificate_with_evidence()
    - oe_verify_attestation_certificate_with_evidence()
- Some SGX attestation format IDs have been renamed:

| Old | New |
| -- | - |
OE_FORMAT_UUID_SGX_ECDSA_P256  | OE_FORMAT_UUID_SGX_ECDSA |
OE_FORMAT_UUID_SGX_ECDSA_P256_REPORT | OE_FORMAT_UUID_LEGACY_REPORT_REMOTE |
OE_FORMAT_UUID_SGX_ECDSA_P256_QUOTE | OE_FORMAT_UUID_RAW_SGX_QUOTE_ECDSA |


### Removed

- COMPILE_SYSTEM_EDL option while building the SDK from source has been removed.
- Declaration of SGX format ID OE_FORMAT_UUID_SGX_ECDSA_P384 is removed.
- oe_get_evidence() support of SGX legacy formats OE_FORMAT_UUID_SGX_ECDSA_P256_REPORT and OE_FORMAT_UUID_SGX_ECDSA_P256_QUOTE is removed.

### Security
- Update mbedTLS to version 2.16.8. Refer to the [2.16.7](https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.7)
  and [2.16.8](https://github.com/ARMmbed/mbedtls/releases/tag/v2.16.8) release notes for the set of issues addressed.

[0.10.0][v0.10.0_log]
------------
### Added
- Added `oe_sgx_get_signer_id_from_public_key()` function which helps a verifier of SGX reports extract the expected MRSIGNER value from the signer's public key PEM certificate.
- OE SDK can now be built and run in simulation mode on a non SGX x64 Windows machine by passing HAS_QUOTE_PROVIDER=off.
  Previously, the build would work, but running applications would fail due to missing sgx_enclave_common.dll.
- OE SDK can now be installed from published packages on SGX machines without FLC, and non-SGX machines.
  Previously, OE SDK could only be installed on SGX1 FLC machines due to a link-time dependency on sgx_dcap_ql which
  was available only on SGX1 FLC machines.
- oesign tool supports the new `digest` command and options for [2-step signing using the digest](
  docs/DesignDocs/oesign_digest_signing_support.md).
- Oeedger8r now supports the --use-prefix feature.
- Oeedger8r now supports a subset of C-style preprocessor directives (#ifdef, #ifndef, #else, #endif).
- The default memory allocator (dlmalloc) can be replaced by providing replacement functions. This ability to plug-in
  a custom allocator is most applicable for multi-threaded enclaves with memory allocation patterns where the default
  memory allocator may not be performant. See [Pluggable Allocators](docs/DesignDocs/Pluggableallocators.md).
- `snmalloc` is available as a pluggable allocator library `oesnmalloc`. An enclave can use snmalloc instead of
  dlmalloc by specifying `liboesnmalloc.a` before `liboelibc.a` and `liboecore.a` in the linker line.
- Added pluggable_allocator sample.
- Gcov is used to obtain code coverage information for the SDK. See [Code Coverage](docs/GettingStartedDocs/Contributors/CodeCoverage.md).
- Added include\openenclave\attestation\attester.h to support attestation plug-in model attester scenarios.
- Added include\openenclave\attestation\verifier.h to support attestation plug-in model verifier scenarios.

### Changed
- `COMPILE_SYSTEM_EDL` is now OFF by default, meaning system EDL must be imported by
  application EDL. See [system EDL opt-in document](docs/DesignDocs/system_ocall_opt_in.md#how-to-port-your-application) for more information.
  - Note: SDK users would need to import logging.edl to enable logging. Logging is disabled by default.
  - See [System edls](docs/SystemEdls.md) for list of all edls and associated OCalls.
  - A known issue is that different enclaves importing functions from System EDLs cannot be loaded by the same host app unless all of the functions were imported with exactly the same ordinals. See #3250 for details. This will be addressed in the next release based on design proposal #3086.
  - A workaround for this issue in the meantime is to define a standard import EDL for any enclaves that need to be loaded into the same host app. Ensuring this shared EDL is then the first import in each enclave's EDL will result in the common imports being assigned the same ordinals in each resulting enclave.
- Mark APIs in include/openenclave/attestation/sgx/attester.h and verifier.h as experimental.
- Remove CRL_ISSUER_CHAIN_PCK_PROC_CA field from endorsement struct define in include/openenclave/bits/attestation.h.
- Switch to oeedger8r written in C++.
- Fix #3143. oesign tool will now reject .conf files that contain duplicate property definitions.
- SGX Simulation Mode does not need SGX libraries to be present in the system.
- oehost library dynamically loads sgx_dcap_ql shared library instead of linking against it. This allows the SDK to
  be installed on non-FLC and non-SGX machines.
- Fix #3134. ParseSGXExtensions will now correctly parse the SGX extensions for PCK Certificates defined in [SGX spec](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_PCK_Certificate_CRL_Spec-1.4.pdf).
- oesign `dump` command now also displays the `MRSIGNER` value of an SGX enclave signature if it exists.
- The Deep-copy feature of oeedger8r is now enabled by default.
- The oeedger8r-generated header files now contain only the function prototypes. Marshalling structs, function id enums,
  and function tables are generated only in the c files.
- Docs and scripts updated to use Azure DCAP client v1.6.0.
- Fix #2930. Fixes the logic of detecting compilers when LVI mitigation is enabled. That is, the old logic always picks clang-7 (if installed) regardless of whether the environment variable CC is set to gcc.
- Fix #2670. This fix also allows users to specify the version of clang (default is clang-7) when building the helloworld sample with LVI mitigation.
- Fix #3056. oe_is_within_enclave() and oe_is_outside_enclave() now reflect the SGX enclave boundary as determined by the enclave SECS rather than the limit of the pages initially provisioned in to the enclave.
- If not specified, CMAKE_BUILD_TYPE is set to Debug. This ensures that cmake and cmake -DCMAKE_BUILD_TYPE=Debug result in the same build configuration.
- Moved include/openenclave/attestation/plugin.h to internal. Currently only support internal attestation plugin registration.
- Parameter _flags_ is removed from experimental function oe_get_evidence(). Use 'evidence_format' parameter to select evidence format.

### Removed
- Removed oehostapp and the appendent "-rdynamic" compiling option. Please use oehost instead and add the option back manually if necessary.
- Removed dependencies on nodejs and esy, which were previously used to build Ocaml compiler and oeedger8r.

### Security
- Fix [ABI poisoning vulnerability for x87 FPU operations in enclaves](
https://github.com/openenclave/openenclave/security/advisories/GHSA-7wjx-wcwg-w999).

[0.9.0][v0.9.0_log]
------------

### Added
- Complete support for inttypes.h and stdlib.h in oelibc. See docs/LibcSupport.md for more details.
- Support for Simulation Mode on Windows. Simulation mode only runs on systems with SGX enabled.
- Support `transition_using_threads` EDL attribute for ecalls in oeedger8r.
  OE SDK now supports both switchless OCALLs and ECALLs.
- Published corelibc headers required by oeedger8r-generated code.
  **Disclaimer:** these headers do not make any guarantees about stability. They
  are intended to be used by generated code and are not part of the OE public
  API surface.
- Support for Windows Server 2019.
- Experimental support for RHEL8.
- Preview versions of VSCode and Visual Studio Extensions for OE are now part of the github repo.
- Experimental support for enclave file system APIs on Windows host.
- oelibcxx now supports up to `std=c++17`. Please see docs/LibcxxSupport.md for more details.
- `COMPILE_SYSTEM_EDL` build flag. This is on by default and will compile system
  OCalls and ECalls into OE libraries as before. If it is set to off, each enclave
  application must import the ECalls/OCalls it needs into its own EDL file from
  `{OE_INSTALL_PATH}/include/openenclave/edl`.
- Experimental support for snmalloc. To use snmalloc, build the SDK from source using -DUSE_SNMALLOC=ON.

### Changed
- Moved `oe_asymmetric_key_type_t`, `oe_asymmetric_key_format_t`, and
  `oe_asymmetric_key_params_t` to `bits/asym_keys.h` from `bits/types.h`.
- Windows host libraries in the Open Enclave NuGet package have been compiled with /WX /W3 enabled.
- Attestation plugin APIs in include/openenclave/attestation/plugin.h are marked experimental.

### Fixed
- Fix #2828 which removes an explicit host side dependency on libsgx-urts on Linux.
- Fix #2607 so that libmbedcrypto now includes mbedtls_hkdf().
- Fix #2786 so that `CXX` is always `TRUE` in `add_enclave_sgx()` and `add_enclave_optee()`.
- Fix #2544 and #2264. This removes oesign's dependency on libsgx_enclave_common and libsgx_dcap_ql.
- Fix #2661 which caused inconsistent code generation in oeedger8r.

### Removed
- Removed oe-gdb script which has been deprecated since v0.6. Use oegdb instead.

### Security
- Update mbedTLS to version 2.16.6. Refer to the [2.16.5](
https://tls.mbed.org/tech-updates/releases/mbedtls-2.16.5-and-2.7.14-released)
and [2.16.6](https://tls.mbed.org/tech-updates/releases/mbedtls-2.16.6-and-2.7.15-released)
release notes for the set of issues addressed.

### Deprecated
- oehostapp is being deprecated from cmake targets. Use oehost instead. See #2595.
- In the next release (v0.10), system EDL will no longer be compiled into OE
  libraries by default (COMPILE_SYSTEM_EDL will be OFF by default). See the
  [system EDL opt-in document]
  (docs/DesignDocs/system_ocall_opt_in.md#how-to-port-your-application) for
  more details on how to rebuild the SDK to match this behavior and for
  guidance on porting your application to the new model.


[v0.8.2][v0.8.2_log] - 2020-03-10
---------------------

### Added
- OpenSSL engine support to oesign to allow signing keys via engines.
- NuGet package validation using CI/CD.
- Released packages include Load Value Injection(LVI) mitigated libraries, required build configuration and instructions.

### Changed
- Optimized switchless ocall scheduling.
- oedebugrt.pdb is part of the SDK package and needs to be copied to the host application folder along with oedebugrt.dll to enable debugging on Windows.

### Security
- OpenEnclave SDK includes LVI mitigated libs and an LVI mitigation build configuration for the vulnerability disclosed in CVE-2020-0551.
   - Applications built on top the SDK can optionally link against the mitigated libs using the LVI mitigation build configuration.
   - See [LVI Mititgation Documentation](docs/GettingStartedDocs/Contributors/AdvancedBuildInfo.md#lvi-mitigation) for more information.

[v0.8.1][v0.8.1_log] - 2020-02-07
---------------------

### Fixed
- Fixed Jenkins pipeline to produce a valid open-enclave NuGet package. Fixes #2523.

### Changed
- `oe_random()` now depends on the hardware-based source of RNG instead of cryptography libraries.
- OCall stack-stitching implemented as per Debugging Contract. OE SDK performs stack stitching
  instead of the debugger. Enclaves built using a prior release cannot be debugged with this version
  of oegdb and vice versa.

[v0.8.0][v0.8.0_log] - 2020-01-22
---------------------

### Added

- Support for backtracing in debug and release builds.
    - Implementations for GNU functions `backtrace` and `backtrace_symbols` (defined in execinfo.h)
    - Enclaves are built using `-fno-omit-frame-pointer` for accurate backtraces.
- Support for custom attestation data formats via new plugin model. Please refer to the [design documentation](docs/DesignDocs/CustomAttestation.md).
- Support for host side sockets on Windows.
- Support to build OE enclave libraries with stack protector enabled.
    - Enable `-fstack-protector-strong` by default for enclave application build configurations in cmake and pkgconfig.

### Changed

- Open Enclave SDK is now officially an incubation project as part of the Linux
  Foundation's Confidential Computing Consortium (CCC).
    - All contributions are now accepted under the terms of the [Developer Certificate
      of Origin](https://developercertificate.org). For details, see
      [Contributing to Open Enclave](docs/Contributing.md).
    - The copyright for all sources is now attributed to Open Enclave SDK contributors.
- Update Intel DCAP library dependencies to 1.4.1.
- Update Intel PSW dependencies to 2.6.100.2 on Windows.
- Enable `/W2 /WX` on Windows builds by default to treat W2 warnings as errors.
- Removed code related to deprecation of strftime.
- Enclave libs and enclaves are built using `-gc-sections`.
- Replace OCPWin and OCaml with esy. The CMake-driven OCaml build is replaced with esy and dune. To install esy as a prerequisite:
      - On Linux, `sudo ansible-playbook oe-linux-esy-setup.yml`
      - On Windows, `npm install -g esy@0.5.8`
- Update Ansible dependency from 2.8.0 to 2.8.2 in /scripts/ansible.
- safecrt.h and safemath.h are not installed as part of the SDK as they are meant for internal consumption.

### Fixed

- `oe_random()` now correctly returns a fully filled byte buffer for requests of > 1024 bytes.
- Add `openenclave` namespace to dl and crypto libraries to prevent symbol collisions. Fixes #2082.

### Deprecated

- `bits/safecrt.h` and `bits/safemath.h` are not published anymore. They were not intended
  for use by enclave authors. They are now moved to internal folder and not part of
  published headers.

### Security

- Update mbedTLS to version 2.16.4. Refer to [2.16.3](
https://tls.mbed.org/tech-updates/releases/mbedtls-2.16.3-and-2.7.12-released) and
[2.16.4](https://tls.mbed.org/tech-updates/releases/mbedtls-2.16.4-and-2.7.13-released)
release notes for the set of issues addressed.

[v0.7.0][v0.7.0_log] - 2019-10-26
---------------------

### Added

- Support Intel DCAP attestation on Windows.
- Support `transition_using_threads` EDL attribute in oeedger8r.
    - This only applies to untrusted functions (ocalls) in this release.
    - Using this attribute allows the ocall to be invoked without incurring the
      performance cost of an enclave context switch.
- Ability to debug ELF enclaves on Windows using Windbg/CDB
    - [Visual Studio Code CDB Extension](https://aka.ms/CDBVSCode)
    - [WinDbg Preview](https://aka.ms/WinDbgPreview)
    - The new oedebugrt.dll and accompanying oedebugrt.pdb need to be copied to the
      app folder to enable this.
- Preview support for 64-bit ARM TrustZone-capable boards with OP-TEE OS
  - See the [documentation](docs/GettingStartedDocs/OP-TEE/Introduction.md)
    for the list of supported platforms, features, and known issues.

### Changed

- Transferred repository from [microsoft/openenclave](https://github.com/microsoft/openenclave)
  to [openenclave/openenclave](https://github.com/openenclave/openenclave).
- Change debugging contract for oegdb. Enclaves and hosts built prior to this
  release cannot be debugged with this version of oegdb and vice versa.
- Update Intel DCAP library dependencies to 1.3.
- Update Intel PSW dependencies to 2.7 on Linux and 2.5 on Windows.
- SGX1 configurations always take build dependency on Intel SGX enclave common library.
- Update LLVM libcxx to version 8.0.0.
- Update mbedTLS to version 2.16.2.

### Deprecated

- The mbedTLS libraries used in Open Enclave will no longer be compiled with the
  following config.h options in the next (v0.8) release:
    - `MBEDTLS_TLS_DEFAULT_ALLOW_SHA1_IN_KEY_EXCHANGE`: Considerable advances
      have been made in breaking SHA1 since our original review and we would
      like to be more prescriptive in recommending the use of SHA256.
    - `MBEDTLS_KEY_EXCHANGE_RSA_ENABLED`: This option provides no perfect
      forward secrecy and is generally becoming less popular as this is
      recognized. The ECDHE variants are also more performant.

### Security

- Fix enclave heap memory disclosure (CVE-2019-1369).

[v0.6.0][v0.6.0_log] - 2019-06-29
---------------------

### Changed

- Rename `oe-gdb` to `oegdb` for consistency with other tools, such as `oesign`.
- Update pkg-config and CMake exports to include the following hardening build
  flags by default:
    - Enclaves will:
       - Compile with `-fPIE` instead of `-fPIC`.
       - Link with `-Wl,-z,noexecstack`, `-Wl,-z,now`.
    - Host apps will:
       - Compile with `-D_FORTIFY_SOURCE=2` (only effective if compiling under
         GCC with `-O2` specified) and `-fstack-protector-strong`.
       - Link with `-Wl,-z,noexecstack`.
       - Note that `-Wl,-z,now` is _not_ enabled by default, but app authors
         should enable it themselves after assessing its startup impact.
- Removed support for the previously deprecated `OE_API_VERSION=1` APIs.
- Update MUSL libc to version 1.1.21.
- Update mbedTLS to version 2.7.11.

[v0.5.0][v0.5.0_log] - 2019-04-09
---------------------

### Added

- Open Enclave SDK works in Windows
   - Build using Visual Studio 2017's CMake Support
   - Build in x64 Native Prompt using Ninja
- Function table/id based ecall/ocall dispatching
   - oeedger8r generates ecall tables and ocall tables
   - Dispatching based on function-id (index into table)
   - oeedger8r generates `oe_create_foo_enclave` function for `foo.edl`
   - oe-gdb allows attaching to a host that is already running
- oe-gdb allows attaching to a host that is already running
- Added Quote Enclave Identity validation into `oe_verify_report` implementation
- Added OE SDK internal logging mechanism
- Support for thread local variables
   - Both GNU `__thread` and C++11 `thread_local`
   - Both hardware and simulation mode
   - Enclaves are compiled using local-exec thread-local model (-ftls-model=local-exec)
- Added `oe_get_public_key` and `oe_get_public_key_by_policy` host functions,
  which allow the host to get a public key derived from an enclave's identity.
- Added v2 versions of the following APIs that instead of passing in buffers now
  return a buffer that needs to be freed via an associated free method. `OE_API_VERSION`
  needs to be set to 2 to pick up the versions. The mentioned APIs have a *_V1 and *_V2
  version that the below versions map to detending on the `OE_API_VERSION`.
   - `oe_get_report`, free `report_buffer` via `oe_free_report`
   - `oe_get_target_info`, free `target_info_buffer` via `oe_free_target_info`
   - `oe_get_seal_key`, free `key_buffer` and `key_info` via `oe_free_seal_key`
   - `oe_get_seal_key_by_policy`, free `key_buffer` and `key_info` via `oe_free_seal_key`
- Added new enumeration for enclave type parameter of `oe_create_enclave`. Now use
  `OE_ENCLAVE_TYPE_AUTO` to have the enclave appropriate to your built environment
  be chosen automatically. For instance, building Intel binaries will select SGX
  automatically, where on ARM it will pick TrustZone.
- Added three new APIs for attestation certificate generation and verification

### Changed

- `oe_create_enclave` takes two additional parameters: `ocall_table` and
  `ocall_table_size`.
- Update mbedTLS library to version 2.7.9.
- Update MUSL libc to version 1.1.20.
- Update LLVM libcxx to version 7.0.0.
   - Some libcxx headers (e.g. `<string>`) now use C++11 template features and
     may require compiling with the `-std=c++11` option when building with GCC.
- Update minimum required CMake version for building from source to 3.13.1.
- Update minimum required C++ standard for building from source to C++14.
- Moved `oe_seal_policy_t`, `oe_asymmetric_key_type_t`, `oe_asymmetric_key_format_t`,
  and `oe_asymmetric_key_params_t` to `bits/types.h` from `enclave.h`.
- Changed minimum required QE ISVSVN version from 1 to 2 for the QE Identity
  revocation check that is performed during quote verification. Remote reports
  that were generated with a QE ISVSVN version of 1 will fail during report
  verification now. To resolve this issue, please install the latest version
  of the [Intel SGX DCAP packages](https://01.org/intel-software-guard-extensions/downloads)
  (1.0.1 or newer) on the system that generates the remote report.
- Revamped `oesign` CLI tool arguments parsing. Instead of relying on the arguments
  order and name, named parameters are used as such:
   - The `sign` subcommand accepts the following mandatory flags:
     - `--enclave-image [-e]`, the enclave image file path
     - `--config-file [-c]`, the path of the config file with enclave properties
     - `--key-file [-k]`, the path of the private key file used to digitally sign the enclave image
   - The `dump` subcommand accepts only the `--enclave-image [-e]` mandatory flag, for the enclave file path.

### Deprecated

- String based `ocalls`/`ecalls`, `OE_ECALL`, and `OE_OCALL` macros.
- `OE_ENCLAVE_TYPE_UNDEFINED` was removed and replaced with `OE_ENCLAVE_TYPE_AUTO`.

### Fixed

- Check support for AVX in platform/OS before setting SECS.ATTRIBUTES.XFRM in enclave.

### Security

- Fix CVE-2019-0876
   - `_handle_sgx_get_report` will now write to the supplied argument if it lies in host memory.
   - Added check for missing null terminator in oeedger8r generated code.

[v0.4.1][v0.4.1_log] - 2018-12-21 (DEPRECATED)
----------------------------------

v0.4.1 contains a small fix to work with Intel's new ISV version bump.

### Changed

- This allows the OE SDK to continue to support reports signed by QE SVN=1,
  and at the same time also allow a newer QE SVN (greater than 1) during the
  oe_verify_report process.

[v0.4.0][v0.4.0_log] - 2018-10-08 (DEPRECATED)
----------------------------------

v0.4.0 is the first public preview release, with numerous breaking changes from v0.1.0
as listed below.

### Added

- Support building Open Enclave SDK apps with Clang-7.
- Support Intel EDL for host & enclave stub generation with oeedger8r tool.
- Support full SGX DCAP remote report (quote) revocation.
- Expand documentation for running on different configurations.
- Add pkg-config files for building Open Enclave apps in C/C++ for GCC or Clang.
- Add data sealing sample.
- Add `oe_call_host_by_address()` to allow enclaves to make OCALLs by callback pointer.
- Add `oe_get_enclave()` to obtain enclave handle to return to host.
- Add `oe_get_target_info()` to support SGX local attestation.
- Add CMake export configuration to SDK (experimental).

### Changed

- Standardize naming convention on new [Development Guide](docs/DevelopmentGuide.md).
- Standardize Open Enclave APIs to use `size_t` type for buffer sizes.
- Standardize Open Enclave APIs to always clear output parameters on error return.
- Change report type detection logic.
   - Reports generated by Open Enclave are no longer transparently usable by Intel SGX SDK.
- Change `oe_identity.authorID` field to `oe_identity.signerID`.
- Clean up thread local storage on return from ECALL.
- Refactor liboecore and liboeenclave dependency.
   - All enclave apps must now link liboeenclave.
- Refactor liboecore and liboelibc dependency.
   - All enclave apps should call libc for C functions instead.
- Break up remote attestation sample into 4 separate samples.
- Simplify `oe_get_report()` so it doesn't accept unused `reportdata` on host side.
- Reduce the set of `oe_result` values returned.
- Update mbedTLS library to version 2.7.5.
- Update LLVM libcxx to version 6.0.1.
- Update MUSL libc to version 1.1.19.
- Update libunwind to version 1.3.

### Deprecated

- Deprecate oe_call_host and oe_call_enclave methods in favor of EDL generated interfaces.

### Removed

- Block re-entrant ECALLs. A host servicing an OCALL cannot make an ECALL back into the enclave.
- Remove oe_thread functions. All enclave apps should use libc/libcxx thread functions instead.
- Remove API reference from SDK package. Refer to https://openenclave.io/apidocs/v0.4 instead.
- Remove outdated documents including DesignOverview.pdf.
- Remove oegen, oedump and oeelf tools.
- Remove CMake-based samples.
- Replace test signing PEM files with runtime generated test keys.

### Fixed

- Add appropriate validations for ELF64 in Open Enclave loader.
- Expand libc/libcxx test coverage.

### Security

- Build all libraries with Clang-7 Spectre-1 mitigation (-x86-speculative-load-hardening).
- Update code to use safe CRT and secure memset/zero memory methods.
- Fix integer overflows and add arithmetic boundary checks in Open Enclave runtime.
- Fix cert chain validation during Open Enclave quote verification.

[v0.1.0][v0.1.0_log] - 2018-06-15 (YANKED)
------------------------------

Initial private preview release, no longer supported.

[Unreleased_log]:https://github.com/openenclave/openenclave/compare/v0.19.0...HEAD

[v0.19.0_log]:https://github.com/openenclave/openenclave/compare/v0.18.5...v0.19.0

[v0.18.5_log]:https://github.com/openenclave/openenclave/compare/v0.18.4...v0.18.5

[v0.18.4_log]:https://github.com/openenclave/openenclave/compare/v0.18.2...v0.18.4

[v0.18.2_log]:https://github.com/openenclave/openenclave/compare/v0.18.1...v0.18.2

[v0.18.1_log]:https://github.com/openenclave/openenclave/compare/v0.18.0...v0.18.1

[v0.18.0_log]:https://github.com/openenclave/openenclave/compare/v0.17.7...v0.18.0

[v0.17.7_log]:https://github.com/openenclave/openenclave/compare/v0.17.6...v0.17.7

[v0.17.6_log]:https://github.com/openenclave/openenclave/compare/v0.17.5...v0.17.6

[v0.17.5_log]:https://github.com/openenclave/openenclave/compare/v0.17.2...v0.17.5

[v0.17.2_log]:https://github.com/openenclave/openenclave/compare/v0.17.1...v0.17.2

[v0.17.1_log]:https://github.com/openenclave/openenclave/compare/v0.17.0...v0.17.1

[v0.17.0_log]:https://github.com/openenclave/openenclave/compare/v0.16.1...v0.17.0

[v0.16.1_log]:https://github.com/openenclave/openenclave/compare/v0.16.0...v0.16.1

[v0.16.0_log]:https://github.com/openenclave/openenclave/compare/v0.15.0...v0.16.0

[v0.15.0_log]:https://github.com/openenclave/openenclave/compare/v0.14.0...v0.15.0

[v0.14.0_log]:https://github.com/openenclave/openenclave/compare/v0.13.0...v0.14.0

[v0.13.0_log]:https://github.com/openenclave/openenclave/compare/v0.12.0...v0.13.0

[v0.12.0_log]:https://github.com/openenclave/openenclave/compare/v0.11.0...v0.12.0

[v0.11.0_log]:https://github.com/openenclave/openenclave/compare/v0.10.0...v0.11.0

[v0.10.0_log]:https://github.com/openenclave/openenclave/compare/v0.9.0...v0.10.0

[v0.9.0_log]:https://github.com/openenclave/openenclave/compare/v0.8.2...v0.9.0

[v0.8.2_log]:https://github.com/openenclave/openenclave/compare/v0.8.1...v0.8.2

[v0.8.1_log]:https://github.com/openenclave/openenclave/compare/v0.8.0...v0.8.1

[v0.8.0_log]:https://github.com/openenclave/openenclave/compare/v0.7.0...v0.8.0

[v0.7.0_log]:https://github.com/openenclave/openenclave/compare/v0.6.0...v0.7.0

[v0.6.0_log]:https://github.com/openenclave/openenclave/compare/v0.5.0...v0.6.0

[v0.5.0_log]:https://github.com/openenclave/openenclave/compare/v0.4.1...v0.5.0

[v0.4.1_log]:https://github.com/openenclave/openenclave/compare/v0.4.0...v0.4.1

[v0.4.0_log]:https://github.com/openenclave/openenclave/compare/v0.1.0...v0.4.0

[v0.1.0_log]:https://github.com/openenclave/openenclave/compare/beb546f...v0.1.0
