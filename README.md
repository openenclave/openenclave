Open Enclave SDK
================

[![Bors enabled](https://bors.tech/images/badge_small.svg)](https://app.bors.tech/repositories/21855)
[![Join the chat at https://gitter.im/openenclave/community](https://badges.gitter.im/openenclave/community.svg)](https://gitter.im/openenclave/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Integration Partners
--------------------

Agnostic Cloud Provider

[![Provider Agnostic Regression Linux](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Agnostic-Linux/badge/icon?subject=Provider%20Agnostic%20Regression)](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Agnostic-Linux/)

Azure

[![Azure Windows](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Azure-Windows/badge/icon?subject=Azure-Windows)](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Azure-Windows/)
[![Nightly Libcxx](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/OpenEnclave-libcxx-tests/badge/icon?subject=Azure%20libcxx%20testing)](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/OpenEnclave-libcxx-tests/)
[![Azure Linux](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Azure-Linux/badge/icon?subject=Azure-Linux)](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/Azure-Linux/)
[![Nightly Packages](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/OpenEnclave-nightly-packages/badge/icon?subject=Nightly%20Packages)](https://openenclaveci.westus.cloudapp.azure.com/job/OpenEnclave/job/Badges/job/OpenEnclave-nightly-packages/)


Introduction
------------

The Open Enclave SDK is a hardware-agnostic open source library for developing
applications that utilize Hardware-based Trusted Execution Environments, also
known as Enclaves.

Open Enclave (OE) is an SDK for building enclave applications in C and C++. An
enclave application partitions itself into two components:
1. An untrusted component (called the host) and
2. A trusted component (called the enclave).

An _enclave_ is a protected memory region that provides confidentiality for data
and code execution. It is an instance of a Trusted Execution Environment (TEE)
which is usually secured by hardware, for example,
[Intel Software Guard Extensions (SGX)](https://software.intel.com/en-us/sgx).

This SDK aims to generalize the development of enclave applications across TEEs
from different hardware vendors. The current implementation provides support for
Intel SGX as well as preview support for OP-TEE OS on ARM TrustZone. As an
open source project, this SDK also strives to provide a transparent solution
that is agnostic to specific vendors, service providers and choice of operating
systems.


Getting Started Using OE SDK
---------------

You'll find comprehensive documentation in the
[Getting Started Guide](docs/GettingStartedDocs).

Contributing to OE SDK
---------------

The [community documentation](docs/Community/) hosts lots of information on
where to go to get engaged with the community, whether you want to contribute
code, add test cases, help improve our documentation, or something else. If
you're looking for information on how to join meetings or who to contact about
what, you will find it there.

You don't necessarily need a hardware enclave to develop OE SDK; some tests and
code paths can be executed in *simulation mode* for the purposes of testing on
non-TEE-enabled hardware.

----

Licensing
---------

This project is released under the
[MIT License](https://github.com/openenclave/openenclave/blob/master/LICENSE).

Send Feedback
=============

Send general questions, announcements, and discussion to the
[oesdk@lists.confidentialcomputing.io Mailing List](https://lists.confidentialcomputing.io/g/oesdk).

To report a problem or suggest a new feature, file a
[GitHub issue](https://github.com/openenclave/openenclave/issues).

To report a security issue, please follow the [process to report a vulnerability](SECURITY.md#reporting-a-vulnerability).
