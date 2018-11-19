SGX and TrustZone
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

## Next Steps

The easiest way to get started with creating a new host and TA pair is by taking
the existing samples and modifying them to suit your needs. 

* [Building a OpenEnclave TrustZone TA on Linux](linux_arm_dev.md)
* [Building a OpenEnclave SGX Enclave on Windows](win_sgx_dev.md)
* [TZ and SGX Together: IoTEdge Socket Sample](sample_edge_sockets.md).
