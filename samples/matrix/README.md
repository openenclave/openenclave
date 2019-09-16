# The matrix sample

- Help understand how to use the VTune profiling feature in an enclave app
- Modified from the matrix multiplication sample in the VTune tutorial

Prerequisite: read [Profiling with VTune](/docs/GettingStartedDocs/VTune.md) before going further

## About the matrix sample

The sample contains a CPU intensive task __matrix multiplication__ in both the enclave and the host side of the application. In this sample you will see:

- The host creates an enclave
- The host runs the matrix multiplication task
- The host calls a simple function in the enclave
- The enclave function runs the matrix multiplication task and then calls a simple function back in the host
- The enclave function returns back to the host
- The enclave is terminated

The basic structure of the sample is based on the [helloworld sample](/samples/helloworld/README.md). The matrix multiplication task under `common` is modified from the VTune sample located under
 `<VTune Installation Dir>/samples/en/C++/matrix`.

## Build and run

Note that only CMake is supported now.

### CMake

```bash
mkdir build && cd build
cmake ..
make run
```

## Run with VTune SGX Hotspot analysis

If you build and install the SDK with `-DVTUNE=1` set, you can run the SGX Hotspot analysis on the application:

```bash
amplxe-cl -collect sgx-hotspot -- <path to this sample>/build/host/matrix_host <path to this sample>/build/enclave/enclave.signed
```

Then open the VTune GUI interface and open the report. You will see that both the host and enclave modules got sampled, and the `multiply` routine dominates the CPU time.
