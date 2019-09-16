# Profiling with VTune

The [Intel VTune Amplifier](https://software.intel.com/en-us/vtune) is a tool provided by Intel to profile your applications. While both the GUI and CLI interfaces are provided, you can only use the CLI for collecting SGX analysis results for now. Nevertheless, you can still use the GUI to view the report.

Before you attempt to use the feature, you should ensure that:

- You are on a linux system with SGX enabled and without using a VM.
- You have `OE_SGX` instead of `OE_TRUSTZONE` set in cmake. The optee environment is currently not supported.
- The enclave is built or signed to allow debugging, and the host app creates the enclave at runtime with the `OE_ENCLAVE_FLAG_DEBUG`. This is detailed in [Debugging enclave memory](Debugging.md).

## Install and configure VTune Amplifier on your system

Refer to the [official document](https://software.intel.com/en-us/vtune-amplifier-help) for how to install VTune on your system. You should also refer to the Sampling Drivers section to install drivers for enabling [hardware event-based sampling](https://software.intel.com/en-us/vtune-amplifier-help-hardware-event-based-sampling-collection).

After VTune is installed, run `source <install-dir>/amplxe-vars.sh` to set up the environment.

Set the environment variables `INTEL_LIBITTNOTIFY32=<VTune Installation Dir>/lib32/runtime/ittnotify_collector.so` and `INTEL_LIBITTNOTIFY64=<VTune Installation Dir>/lib64/runtime/ittnotify_collector.so` to set up the global ITT environment.

**Caution:**

It is advised to have separate sessions for running the VTune application and working with your Open Enclave installation. Some libraries such as `libcrypto.a` might be picked up from a wrong directory due to path conflicts in the VTune and OE environments.

## Build the Open Enclave SDK with VTune feature enabled

The VTune feature is contained in the SDK only if you set the `-DVTUNE=1` flag for cmake when building the Open Enclave SDK.

In the Open Enclave build folder, run the following to build and install the SDK:

```bash
cmake -DVTUNE=1 ..
make
make install
```

## Running the SGX Hotspots analysis with VTune

`SGX Hotspots` is an analysis type in VTune and is currently only supported in CLI. The results can still be viewed with GUI.

To profile with the analysis type, run:

`amplxe-cl -collect sgx-hotspot -- <app> <args>`

The report will be generated under the current directory.

Open the VTune GUI and open the results generated to view the report.

## Samples

We provided a sample adapted from the matrix app in VTune samples to see the profiling results of an enclave application. See [Matrix sample](/samples/matrix/README.md) for details.

### TODO

- Enable profiling for optee
- Enable profiling for Windows

### Known issues

- The profiling cannot be done in a VM without access right to the hypervisor, since hardware event-based sampling collection requires vPMU feature to be enabled in the hypervisor. The error message: "Cannot enable event-based sampling collection: Architectural Performance Monitoring version is 0. Make sure the vPMU feature is enabled in your hypervisor".
