Changelog
=========

Major work such as new features, bug fixes, feature deprecations, and other
breaking changes should be noted here. It should be more concise than `git log`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

[Unreleased][Unreleased_log]
--------------

### Added
- Added `oe_sgx_get_signer_id_from_public_key()` function which helps a verifier of SGX
  reports extract the expected MRSIGNER value from the signer's public key PEM certificate.

### Changed
- Mark APIs in include/openenclave/attestation/sgx/attester.h and verifier.h as experimental.

### Removed
- Removed oehostapp and the appendent "-rdynamic" compiling option. Please use oehost instead and add the option back manually if necessary.

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

[Unreleased_log]:https://github.com/openenclave/openenclave/compare/v0.9.0...HEAD

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
