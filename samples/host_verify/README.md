
# The host-side enclave verification sample

- Demonstrates the attestation of a remote enclave
- Requires only the `openenclave/host_verify.h` header, as well as some C standard header files

Prerequisites: you may want to read [Common Sample Information](../README.md#common-sample-information) before going further

## About the host-side enclave verification sample

When an application is doing host-side enclave verification, it means that a host application is trying to authenticate a remote enclave's hardware and software settings so that the application can determine whether or not to trust the remote enclave.

The sample does remote host-side enclave attestation by taking either of the two arguments:

- An SGX report
- An SGX certificate

The sample also accepts an endorsement file as input. See the end of the file for usage.

A user can generate a report, an endorsement file or a certificate with `oecert`. See [here](https://github.com/openenclave/openenclave/blob/master/tests/tools/oecert/README.md) for more details.

In the main function, if it sees the attribute `-r`, then it will continue to read the next argument to get the report and call `verify_report()` to verify the report.
Likewise, if it sees the attribute `-c`, then it will continue to read the next argument to get the certificate and call `verify_cert()` to verify the certificate.
If it sees the attribute `-h`, it will show the usage of this program.
There is also an `enclave_identity_verifier()` function, which is called by `verify_cert()` and shows the information of a certificate if you feed it to the program.

## Build and run

Open Enclave SDK supports building the sample on both Linux and Windows.
Linux supports two types of build systems, GNU Make with `pkg-config` and CMake,
while Windows supports only CMake.

### Linux

#### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd host_verify
mkdir build && cd build
cmake ..
make run
```

#### GNU Make

```bash
cd host_verify
make build
make run
```

### Windows

#### CMake

```bash
mkdir build && cd build
cmake .. -G Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs
ninja
ninja run
```

When you see the following message displayed on the screen, it means you have successfully run the sample.

```bash
Usage:
  ./host_verify -r <report_file> [-e <endorsement_file>]
  ./host_verify -c <certificate_file>
Verify the integrity of enclave remote report or attestation certificate.
WARNING: host_verify does not have a stable CLI interface. Use with caution.
```
