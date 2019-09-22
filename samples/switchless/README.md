# Switchless Calls Sample

This sample demonstrates how to make switchless calls to host from inside an enclave. It is built on top of the [`Hello World`](../helloworld/README.md) sample. The addition is a host function `host_helloworld_switchless` which is called from the enclave switchlessly.

It has the following properties:

- Explain the concept of switchless calls
- Demonstrate how to mark a function as `transition_using_threads` in EDL, and use [`oeedger8r`](https://github.com/openenclave/openenclave/tree/master/docs/GettingStartedDocs/Edger8rGettingStarted.md) tool to compile it
- Demonstrate how to configure an enclave to enable switchless calls within it

Prerequisite: you may want to read [Common Sample Information](../README.md#common-sample-information) before going further.

## Switchless Calls

In an enclave application, the host makes **ECALL**s into functions exposed by the enclaves it created. Likewise, the enclaves make **OCALL**s into functions exposed by the host that created them. In either case, the execution has to be transitioned from an untrusted environment to a trusted environment, or vice versa. Since the transition is costly due to heavy security checks, it might be more performance advantageous to make the calls **context-switchless**: the caller delegates the function call to a worker thread in the other environment, which does the real job of calling the function and post the result to the caller. Both the calling thread and the worker thread never leave their respective execution contexts during the perceived function call.

The calling thread and the worker thread need to exchange information twice during the call. When the switchless call is initiated, the caller needs to pass the `job` (representing the function call) to the worker thread. And when the call finishes, the worker thread needs to pass the result back to the caller. Both exchanges need to be synchronized.

## How does OE support switchless OCALLs

OE only supports synchronous switchless OCALLs currently. When the caller within an enclave makes a switchless OCALL, the trusted OE runtime creates a `job` out of the function call. The `job` object includes information such as the function ID, the parameters marshaled into a buffer, and a buffer for holding the return value(s). The job is posted to a shared memory region which both the enclave and the host can access.

A host worker thread checks and retrieves `job` from the shared memory region. It uses the untrusted OE runtime to process the `job` by unmarshaling the parameters, then dispatching to the callee function, and finally relaying the result back to the trusted OE runtime, which is further forwarded back to the caller.

To support simultaneous switchless OCALLs made from enclaves, the host workers are multi-threaded. OE allows users to configure how many host worker threads are to be created for servicing switchless OCALLs. The following example illustrates how to do that. A word of caution is that too many host worker threads might increase competition of cores between threads and degrade the performance. Therefore, if a enclave has switchless calls enabled, OE caps the number of host worker threads for it to the number of enclave threads specified.

## About the EDL

First we need to define the functions we want to call between the host and the enclave. To do this we create a `switchless.edl` file:

```edl
enclave {
    trusted {
        public void enclave_helloworld();

    };

    untrusted {
        void host_helloworld();
        void host_helloworld_switchless() transition_using_threads;
    };
};
```

Function `host_helloworld_switchless`'s declaration ends with keyword `transition_using_threads`, indicating it should be called switchlessly at run time. However, this a best-effort directive. OE runtime may still choose to fall back to a tradition OCALL if switchless call resources are unavailable, e.g., the enclave is not configured as switchless-capable, or the host worker threads are busy servicing other switchless OCALLs.

To generate the functions with the marshaling code, the `oeedger8r` tool is called in both the host and enclave directories from their Makefiles. For example:

```bash
cd host
oeedger8r ../switchless.edl --untrusted --experimental
```

`oeedger8r` needs the command line flag `--experimental` to be able to recognize the keyword `transition_using_threads`.

## About the host

The host first defines a structure specifically for configuring switchless calls. In this case, we specify the first field `2` as the number of host worker threads for switchless OCALLs. The 2nd field specifies the number of enclave threads for switchless ECALLs. Since switchless ECALL is not yet implementated, we require the 2nd field to be `0`.

```c
oe_enclave_config_context_switchless_t config = {2, 0};
```

The host then puts the structure address and the configuration type in an array of configurations for the enclave to be created. Even though we only have one configuration (for switchless) for the enclave, we'd like the flexibility of adding more than one configurations (with different types) for an enclave in the future.

```c
oe_enclave_config_t configs[] = {{
        .config_type = OE_ENCLAVE_CONFIG_CONTEXT_SWITCHLESS,
        .u.context_switchless_config = &config,
    }};
```

To make the configurations created above effective, we need to pass the array `configs` into `oe_create_enclave` in the following way:

```c
oe_create_switchless_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             configs,
             OE_COUNTOF(configs),
             &enclave);
```

The host then makes an ECALL of `enclave_helloworld` to transition into the enclave. After the ECALL returns, the host terminates the enclave.

As shown in the EDL file, the host exposes two host functions: `host_helloworld` and `host_helloworld_switchless`. The former prints "Hello world from regular OCALL", and the latter prints "Hello world from switchless OCALL".

## About the enclave

The enclave exposes only one function `enclave_helloworld`. The function prints "Hello world from the enclave" first, then call the host function `host_helloworld`, followed by calling host function `host_helloworld_switchless`. Internally, the last call is fulfilled switchlessly. If everything work as expected, the output of this enclave function would be:

```
Hello world from the enclave
Hello world from regular OCALL
Hello world from switchless OCALL
```

## Build and run

Note that there are two different build systems supported, one using GNU Make and
`pkg-config`, the other using CMake.

### CMake

This uses the CMake package provided by the Open Enclave SDK.

```bash
cd switchless
mkdir build && cd build
cmake ..
make run
```

### GNU Make

```bash
cd helloworld
make build
make run
```
#### Note

switchless sample can run under OE simulation mode.

To run the switchless sample in simulation mode from the command like, use the following:

```bash
# if built with cmake
./host/switchless_host ./enclave/switchless_enc.signed --simulate
# or, if built with GNU Make and pkg-config
make simulate
```
