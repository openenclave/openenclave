Plugin Architecture
=====

This document describes the principles behind the Open Enclave plugin
architecture and establishes the framework for third-party testing of those
plugins.


Motivation
-----

Set and communicate clearly our "north star" for enabling a community-driven
development model, creating a strong abstraction layer to support
standardization across all enclaves while balancing the need to innovate
quickly and adapt to new developments in hardware.


User Experience
------

Any developer wishing to contribute a new plugin should read this document to understand
the overall principles behind our plugin architecture, and how to integrate testing
of their plugin to build community confidence in the code quality.

Specific APIs will be defined in other documents.


Specification
------

In the Open Enclave/plugin directory, a set of stubs (emulators) will be
implemented, which facilitate testing of as much of the in-tree code as
possible without relying on a physical hardware TEE. Virtual TEEs may be
employed, and other forms of emulation may be considered and added in the
future.

This "stub" also serves as a template for anyone to create a hardware-specific
plugin. As such, the "stub" code should be of the highest quality. It should
implement all function calls, and demonstrate the expected coding standards
which the Open Enclave community holds all contributors to.

Hardware-specific code should be contributed within an out-of-tree plugin.

Additionally, hardware-specific plugins should be tested in third-party CI/CD
environments which subscribe to GitHub change notifications and posts the
results of their tests back to GitHub PRs for review. The community should
monitor the health of these test systems. These test results should be
considered advisory input when accepting any PR, and may be considered gating
for changes, at the discretion of project maintainers.

See this diagram for [an overview of the plugin architecture](images/plugin-architecture-and-cicd.svg).


Alternatives
------

One alternative is to keep all hardware plugins in-tree. It is believed that
this approach would place a burden on project maintainers who may not have the
hardware resources necessary to adequately evaluate hardware-specific plugins.

Authors
------

Aeva Marie van der Veen (aevander at microsoft dot com)

