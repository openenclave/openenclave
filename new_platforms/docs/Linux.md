Linux Support
=============

# Overview

The Open Enclave SDK allows you to develop applications that take advantage of
Trusted Execution Environments, or TEE's. Such applications are always composed
of two components: an untrusted component and a trusted component. The trusted
component contains the program logic that operates on sensitive data while the
untrusted component acts as a facilitator which launches and performs actions on
behalf of the trusted component. It is crucial to note that the untrusted
component must never be exposed to sensitive data as it exists outside of the
trust boundary.

The Open Enclave SDK supports two TEE technologies: Intel's Software Guard
Extensions (SGX) and ARM TrustZone (TZ). Due to the way these technologies were
developed, the nomenclature used to refer to equivalent aspects of the two are
different. The documentation at hand uses these different but otherwise
synonymous words interchangeably, so it is worthwhile to briefly mention them.
The untrusted component is usually referred to as the "host" for both SGX and
TrustZone. The trusted component is referred to as an "enclave" in the world of
SGX while it is referred to as a "trusted application" or "TA" for short in the
realm of TrustZone.

By definition, TEE's are meant to separate sensitive logic and sensitive data
from the untrusted components of a software system. In this sense, all programs
that do not execute inside the TEE are said to execute in the Rich Execution
Environment, or REE. The reason for the "rich" characterization is derived from
the observation that TEE's offer restricted functionality in view of reducing
the attack surface for a malicious actor. As such, one may regard the REE and
one or more TEE's as components that exist, but do not necessarily execute, in
parallel.

## Intel SGX Enclaves

In an SGX environment, a host application running in REE user-mode may launch
one or more enclaves. These enclaves may be regarded as secure islands in an
untrusted sea. Each island is isolated from one another and from the sea at
large, which includes the host, all other user-mode programs, as well as the
operating system, hypervisor (if any), and firmware:

```
  | ============= |    | ============= |    | ============= |
  |   Enclave A   |    |   Enclave A   |    |   Enclave B   |
  |  Instance #1  |    |  Instance #2  |    |  Instance #1  |
  | ============= |    | ============= |    | ============= |
          |                    |                    |
          |--------------------|                    |
          |                                         |
  | ------------ |                          | ------------ |
  |  Host App A  |                          |  Host App B  |
  | ------------ |                          | ------------ |

User-Mode
===============================================================
Kernel-Mode
             OS 1           |             OS 2
===============================================================
                        Hypervisor                     
===============================================================
                         Firmware
```

## ARM TrustZone Trusted Applications

In TrustZone, a host application running in the REE may create one or more
sessions with one or more trusted applications. Instances of sessions with
trusted applications are mediated by a kernel-mode component running in the TEE:
OP-TEE OS. OP-TEE OS is not a traditional operating system. Rather, it aids in
the boot process and provides trusted applications with basic services. One such
service is communication with host applications.

One may conceptualize TrustZone by considering the isolation between firmware,
hypervisor, operating system and user-mode. This isolation occurs in horizontal
layers. ARM TrustZone introduces a vertical dimension to this layering,
effectively duplicating several of these layers in a TEE:

```
           Normal World (REE)               Secure World (TEE)

  | ------------ |  | ------------ |  ||  | ------ |  | ------ | 
  |  Host App A  |  |  Host App B  |  ||  |  TA 1  |  |  TA 2  |
  | ------------ |  | ------------ |  ||  | ------ |  | ------ |
                                      ||
User-Mode                             ||
======================================||==========================
Kernel-Mode                           ||
            OS 1 | OS 2               ||          OP-TEE
======================================||==========================
             Hypervisor               ||           N/A
======================================||==========================
                                   Firmware
```
**Note**: This picture shows the ARMv8 architecture. ARMv7 is similar, but not
quite the same.

## Open Enclave's Role

This document has thus far not made any mention of a specific operating system.
This is because TEE's are enforced by hardware, not software. As such, any
operating system with the appropriate support may fulfill that role. The host
application however is dependent on the operating system, and the trusted
component must adapt to the requirements of the backing TEE, either SGX or
TrustZone. As a result, there are four possible combinations:

* A host application on Linux:
    * With SGX enclaves;
    * With TrustZone trusted applications.
* A host application on Windows:
    * With SGX enclaves;
    * With TrustZone trusted applications.

The Open Enclave SDK is a framework that allows you to write your host
applications and your trusted components not against an operating system or a
TEE technology, respectively. Rather, you target your programs against the Open
Enclave SDK and it in turn deals with the specificities of any one operating
system or TEE.

For the purposes of this public preview, the remainder of this document is
focused on how to write host applications on Linux and trusted applications on
TrustZone.

# Working with the SDK

This section shows you how to obtain and build the SDK as well as the samples
and test code that it includes.

**Note**: The only currently supported build environment is Ubuntu 18.04.1.

## Getting the SDK

Fetching the sources for the Open Enclave SDK on Linux is no different than
doing so on Windows, all you need is Git:

```
git clone --recursive https://github.com/ms-iot/openenclave
```

## Building the SDK

The Open Enclave SDK has a top-level CMake-based build system. However, Linux
support is limited to building via GNU Make for this public preview. A Bash
script is also provided that automates the process of installing all
prerequisites and invoking the relevant Makefiles.

Due to the design of ARM TrustZone, trusted applications must be compiled once
for each specific board you want to run them on. OP-TEE OS provides a layer of
abstraction atop raw hardware and may either be readily built by your hardware
provider or you may build it yourself. OP-TEE OS has support for a variety of
ARM boards and, when it is built, it produces a TA Development Kit not
dissimilar to an SDK. This kit includes header files with definitions for
standard functions as well as GNU Make rules that specify how TA code is to be
built and packaged. As a result, to build a TrustZone TA, you either must have
access to the TA Dev Kit that corresponds to the version of OP-TEE on your board
or you must build it yourself.

For convenience, the Bash script included with the Open Enclave SDK can build
OP-TEE OS for the purposes of obtaining a TA Dev Kit for certain specific
configurations. The configurations are specified using two variables:

* `ARCH` specifies the target architecture:
    * `aarch32` for ARMv7 targets;
    * `aarch64` for ARMv8 targets.
* `MACHINE` specifies the target board.
    * For ARMv7 targets:
        * `virt` builds OP-TEE OS and creates a TA Dev Kit for running emulated
          in QEMU (`qemu-system-arm`).
    * For ARMv8 targets:
        * `ls1012grapeboard` builds OP-TEE OS and a TA Dev Kit for a Scalys
          LS1012 (Grapeboard) board;
        * `virt` builds OP-TEE OS and a TA Dev Kit for running emulated in QEMU
          (`qemu-system-aarch64`).

For example, to build the Open Enclave SDK, its samples and test code for the
LS1012, do the following after cloning:

```
cd Open Enclave/new_platforms

export IntelSGXSDKInstallerURI=https://tcpsbuild.blob.core.windows.net/tcsp-build/SGXSDK.zip
export ARCH=aarch64
export MACHINE=ls1012grapeboard

./build_optee.sh
```

This command performs the following steps:

* Installs all build prerequisites;
* Downloads and extracts the Linaro cross-compilers:
    * For `aarch32`, only the arm-on-x86/64 cross-compiler is necessary;
    * For `aarch64`, the aarch64-onx86/64 is necessary in addition to the
      arm-on-x86/64 cross-compiler.
* Downloads and extracts the SGX SDK for Linux*;
* Downloads the `oeedger8r` tool;
* Builds OP-TEE OS and the associated TA Dev Kit;
* Builds the Open Enclave SDK with samples and test code;
* Executes Doxygen on the SDK.

## Bring Your Own OP-TEE

If you already have a TA Dev Kit, you may specify it as follows just prior to
invoking the script:

```
export TA_DEV_KIT_DIR=<absolute path to the kit>
```

This precludes the script from building OP-TEE and it instead references your TA
Dev Kit.

## Cleaning the SDK

To remove all output generated by the script, run:

```
export ARCH=<arch to clean>
export MACHINE=<machine to clean>
export TA_DEV_KIT_DIR=<only if you had specified your own before>

./build_optee.sh clean
```

# Understanding the SDK

To understand how to build a host and TA, this section examines one of the
samples included with the Open Enclave SDK. These samples are found under
`new_platforms/samples`.

This section examines the `sockets` sample. This sample consists of two hosts
and one TA. The TA contains both server and client functionality used by both
hosts. The server host invokes the server functionality in the TA and the client
host invokes the client functionality. Server and client exchange simple text
messages over a TCP/IP socket.

##  Sample Structure

This is the folder structure of the `sockets` sample:

```
new_platforms/samples/sockets/
    | SampleTA.edl
    | Trusted
        | SampleTA.c
        | SampleTA.vcxproj
        | optee
            | linux_gcc.mak
            | sub.mak
            | user_ta_header_defines.h
    | Untrusted
        | ClientServerApp
            | main.c
            | Makefile
            | ClientServerApp.vcxproj        
        | SampleServerApp
            | main.c
            | Makefile
            | SampleServerApp.vcxproj
```

The `SampleTA.edl` file describes the interface via which the host and TA
communicate with one another. This EDL file contains only functionality that is
specific to the sample. However, it references other EDL files provided by the
Open Enclave SDK. These referenced EDL files specify the interface through which
the trusted components of the SDK, which are linked into your TA, and the
corresponding untrusted components of the SDK, which are linked into your host
app, talk with each other. The `oeedger8r` tool processes this file and
generates code that may be called by either the trusted or the untrusted side to
transparently communicate with the other side.

Under the `Trusted` folder there is a single `SampleTA.c` file. This file
contains all the TA's functionality. Note how there is no TEE-specific code:
nothing is specific to either Intel SGX or ARM TrustZone, these details are
taken care of by the SDK.

Next, there is a Visual Studio project file. This file is used by Visual Studio
on Windows to build this TA as an Intel SGX enclave. Similarly, under the
`optee` folder are Makefiles that are consumed by the OP-TEE TA Dev Kit to
produce an OP-TEE-compatible TA. Both the Visual Studio project and the
Makefiles reference `SampleTA.c`.

Lastly, there is a file called `user_ta_header_defines.h`. This file is also
consumed by the OP-TEE TA Dev Kit and it specifies the UUID of the TA as well as
other OP-TEE-specific parameters. You must fill these values in in accordance
with how you plan to use the TA. In this instance, you will need to understand
how OP-TEE loads and manages sessions with TA's in order to configure yours
properly. Each TA must have a unique UUID.

Under the `Untrusted` folder there are two more folders: `ClientServerApp` and
`SampleServerApp`. These folders contain the client and server host programs,
respectively.

Under the first folder there is a `main.c` file. This file contains OS- and
TEE-agnostic host code that loads the TA and invokes the client-related
functionality. Note that the code that you write for your host need not know how
to launch an enclave under Intel SGX or a TA under ARM TrustZone nor how to do
so under both Windows and Linux. Again, the Open Enclave SDK deals with these
details on your behalf. The `SampleServerApp` folder follows the same
principles.

In general then, there is an EDL file that both the trusted and untrusted
components consume that specifies how the pair communicate across the trust
boundary. The EDL file only contains functions that are specific to your
use-case. The trusted component need only be written once and targets the Open
Enclave SDK's API. This way it can be seamlessly compiled as an Intel SGX
enclave and as an ARM TrustZone trusted application. Similarly, the host
programs also need only be written once and, assuming you do not make use of
OS-specific functionality, they too can be compiled into Windows and Linux
programs that can seamlessly launch and operate Intel SGX enclaves and ARM
TrustZone trusted applications.

## Dependencies

The trusted component depends on the following Open Enclave-provided libraries:

* oeenclave: Provides core Open Enclave functionality;
* oesocket_enc: Provides sockets functionality inside the TA:
    * Linking is necessary only if you use sockets;
    * This library marshals socket calls out to the host.
* oestdio_enc: Provides standard I/O functionality inside the TA:
    * Linking is necessary only if you use standard I/O;
    * This library marshals standard I/O calls out to the host.

You can see these libraries being listed in the `sub.mk` file under
`Trusted/optee` and in the corresponding Visual Studio project file. The
sub-makefile includes `oe_sub.mk` which specifies `oeenclave`.

**Note**: When using sockets or I/O API's, or any other trusted-to-untrusted
call, the data that you send into these API's and out to the host is not
automatically protected.

The untrusted component depends on the following Open Enclave-provided
libraries:

* oehost: Provides core Open Enclave functionality;
* oesocket_host: Provides the implementation of the socket calls that the
  trusted component makes:
    * Linking is necessary only if you use sockets inside the trusted component.
* oestdio_host: Provides the implementation of the standard I/O calls that the
  trusted component makes:
    * Linking is necessary only if you use standard I/O inside the trusted
      component.

Notice how these libraries come in pairs. The libraries provide Open
Enclave-provided API's inside the trusted component. When you call these API's,
they in turn invoke code generated by the `oeedger8r` tool as specified by the
SDK's EDL files, included by yours. This code marshals the calls across the
trust boundary which are captured by functions implemented in the corresponding
libraries on the host. The same is true the other way around.

## Next Steps

The easiest way to get started with creating a new host and TA pair is by taking
the existing samples and modifying them to suit your needs. The `sockets` sample
is simple in nature but provides all the structure you need to be well on your
way to creating your own TEE-enabled applications.
