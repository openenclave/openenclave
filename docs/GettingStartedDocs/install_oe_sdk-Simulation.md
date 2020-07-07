# Install the Open Enclave SDK (non-SGX Ubuntu 16.04/18.04)

## Considerations
The Open Enclave SDK can be installed on non-SGX Ubuntu 16.04 and 18.04 systems. Ensure your machine has an Intel processor. It can also be used in simulation mode, although some features may not work. Specifically these features are not supported when running in simulation mode:
- Enclave signing and measurement
- Data Sealing
- Attestation (both remote and local)
- Signal handling (specifically: the oe_add_vectored_exception_handler and oe_remove_vectored_exception_handler APIs)

Only four of the samples provided in the Open Enclave SDK will function in simulation mode:
- helloworld
- file-encryptor
- pluggable_allocator
- switchless

Note that enclaves that are run in simulation mode are not protected by a trusted execution environment. Therefore, simulation mode should only be used for prototype scenarios and validating ocall/ecalls.
Also note that simulation mode is subject to being fundamentally changed or removed in the future.

## How to install and use the SDK for Simulation mode

Follow one of the docs below for your platform, _and skip the driver installation step (step #2)_:
- [Ubuntu 16.04](install_oe_sdk-Ubuntu_16.04.md)
- [Ubuntu 18.04](install_oe_sdk-Ubuntu_18.04.md)

To run an enclave in simulation mode, the enclave must be created with the `OE_ENCLAVE_FLAG_SIMULATE` flag set.
For example, when calling `oe_create_***_enclave`, the `flags` parameter should have `OE_ENCLAVE_FLAG_SIMULATE`, like this:
```
    result = oe_create_helloworld_enclave(argv[1], OE_ENCLAVE_TYPE_AUTO, OE_ENCLAVE_FLAG_SIMULATE, NULL, 0, &enclave);
```

Each of the samples that support simulation mode can be run in simulation mode by running `make simulate`.
