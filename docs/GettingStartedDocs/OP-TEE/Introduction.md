# Open Enclave SDK for OP-TEE OS

Each Trusted Execution Environment (TEE) implementation provides a different
model with respect to the interaction between hosts and enclaves, as well as
regarding the runtime behavior of the two.

The TEE implemented by ARM TrustZone splits the system into a secure and a
non-secure mode, where each keep their user-mode/kernel-mode partition. Hence,
an enclave that leverages ARM TrustZone executes in secure user-mode whereas its
host executes in non-secure user-mode:

```
            |=============================================|
            |   Non-Secure Mode    |     Secure Mode      |
            |=============================================|
            |                      |                      |
            |      Host #1         |  Enclave #1          |
            |                      |                      |
   User     |         Host #2      |          Enclave #2  |
   Mode     |                      |                      |
            |---------------------------------------------|
  Kernel    |                      |                      |
   Mode     |         Linux        |      OP-TEE OS       |
            |                      |                      |
            |=============================================|
```

While Linux operates in the usual way in non-secure kernel-mode, OP-TEE OS
fulfills the role of the kernel in secure mode.

OP-TEE OS provides a low-level communication mechanism to Linux based on the ARM
Secure Monitor Call (`smc`) instruction. In turn, Linux incorporates an OP-TEE
driver that enables Linux to talk to OP-TEE. This driver plugs into a generic
TEE driver, which exposes its capabilities to user-mode. There, a library known
as the OP-TEE Client (`libteec`) may be leveraged by non-secure user-mode hosts
to load, communicate with, and terminate enclaves.

Likewise, OP-TEE OS provides a number of system calls to secure user-mode. A
library is in turn provided (`libutee`) that enclaves can use to call into these
system services.

The Open Enclave SDK for OP-TEE OS effectively implements the SDK's APIs and
behaviors atop those exposed by OP-TEE OS both to non-secure user-mode as well
as atop those exposed to secure user-mode.

**Note:** OP-TEE OS refers to enclaves as "Trusted Applications" (TAs). This
guide, as well as those linked at the bottom, use the term "enclave" to remain
in line with the SDK's nomenclature. However, when working with OP-TEE OS, such
as reading its debug output, you will come across "TA" frequently.

## Supported Features

The SDK currently provides preview support for the following features on OP-TEE
OS:

1. Building Hosts & Enclaves
   1. Linux Hosts
   2. ARM64 Enclaves
2. Loading Enclaves
3. C/C++
4. Enclave Calls (ECALLs)
5. Out Calls (OCALLs)
6. Terminating Enclaves

### Known Issues

#### C++ exceptions are not fully supported

Even though it is possible to write enclaves that use C++ exceptions and run
them on OP-TEE OS, the stack unwinder may fail to find an exception handler on
`throw`.

[Tracking issue](https://github.com/openenclave/openenclave/issues/2274).

#### OP-TEE test suite failure

One of OP-TEE's test cases is known to fail on the TrustBox.

[Tracking issue](https://github.com/openenclave/openenclave/issues/2275).

### 32-bit targets are not supported

[Tracking issue](https://github.com/openenclave/openenclave/issues/2493).

## Note on Forks

While the SDK's support for Intel SGX is fairly self-contained, support for
OP-TEE OS mandates interactions among several components that exist outside the
purview of Open Enclave.

Currently, the SDK works atop forks of the following projects:

1. Linux
   1. The TEE and OP-TEE drivers have been modified.
   2. [Fork](https://github.com/ms-iot/linux/tree/ms-iot-openenclave-3.6.0)
2. OP-TEE OS
   1. The OS was augmented to support OCALLs.
   2. [Fork](https://github.com/ms-iot/optee_os/tree/ms-iot-openenclave-3.6.0)
3. OP-TEE Client
   1. The library was provided with the ability to handle OCALL requests.
   2. [Fork](https://github.com/ms-iot/optee_client/tree/ms-iot-openenclave-3.6.0)

The changes to these are in the process of being upstreamed. For the moment, to
leverage the SDK's support for OP-TEE OS, be it on hardware or on an emulator,
Open Enclave's forks of these projects must be used.

See the list of supported platforms below for instructions on how to use these
forks.

## Binary Packages

The Open Enclave SDK for Intel SGX may be installed on Linux and Windows systems
via binary packages. For the moment, there is no support for these for OP-TEE
OS. As a result, building hosts and enclaves for OP-TEE OS with the SDK requires
building the SDK from source.

To do so, follow the instructions
[here](../Contributors/OPTEEGettingStarted.md).

## Debugging

OP-TEE OS does not provide any debugging facilities. Hence, it is not possible
to debug enclaves using a software debugger once these have been deployed to
hardware. However, it is possible to debug enclaves prior to deployment using
hardware emulation; for details, see the next section. Additionally, for boards
that support it, it is possible to debug enclaves with a JTAG debugger.

## Supported Platforms

The Open Enclave SDK currently provides preview support for the following
platforms:

- Hardware
   1. Scalys TrustBox
      - [Website](https://scalys.com/trustbox-industrial)
      - [Getting Started Guide](Hardware/ScalysTrustBox.md)
- Emulation
   1. The Quick EMUlator (QEMU)
      - [Website](https://www.qemu.org)
      - [Getting Started Guide](Debugging/QEMU.md)
