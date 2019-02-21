Working with the LS1012 Grapeboard
=============
The supported board for this preview of ARM TrustZone using the Open Enclave SDK is the Scalys [Grapeboard](https://www.grapeboard.com/),
 based on the NXP Layerscape LS1012A SoC. This SoC that integrates a hardware root of trust, cryptographic accelerators, and network acceleration.

 For this preview, only Linux is supported as the host.

## Getting Started

To use your Grapeboard, you first need to build all the components necessary to boot the device.
This includes U-Boot, OP-TEE, Linux, and others. NXP provides the Layerscape SDK (LSDK) to automate this process.

To fullfil the Open Enclave SDK requirements, the device firmware must provide the necessary security guarantees.
These include a cryptographic hardware protected identity, authenticated and measured boot, among others.
The reference firmware used is built on open standards, such as the [TCG DICE architecture](https://trustedcomputinggroup.org/work-groups/dice-architectures/).
The reference firmware also enables OCALL-like functionality in OP-TEE and Linux, allowing a TA to support the SGX enclave-like ECALL/OCALL pattern.
This reference design is available as part of the [ms-iot/LSDK](https://github.com/ms-iot/lsdk). 

### Building Your Grapeboard
Follow the Getting Started on [LS1012 Grapeboard guide](https://github.com/ms-iot/lsdk/blob/master/Readme.md) to download, build, and flash all the firmware needed.

## Connecting to your Device

The easiest way to get connected to your Grapeboard for development is through a serial connection.
Follow [these steps](https://github.com/ms-iot/lsdk/blob/master/docs/grapeboard.md#serial-terminal) to get going.

## Building the Open Enclave SDK

Once you have your Grapeboard up and running, you can now use it to run your ARM TrustZone TAs built with the Open Enclave SDK.
If you haven't already, you need to build the host apps and TAs on a Linux Host:

* [Building a Open Enclave TrustZone TA on Linux](linux_arm_dev.md)
* [Running a SampleClient on the Grapeboard](sample_sockets.md#grapeboard)
