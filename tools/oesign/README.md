# oesign - HOWTO

## oesign sign

The `oesign` tool should be used with the subcommand `sign` to sign enclaves. The samples show how a developer should use this tool to sign their enclaves before using them. Please refer to how one of the samples uses this tool here: https://github.com/Microsoft/openenclave/blob/master/samples/helloworld/enclave/Makefile

To understand the full CLI of this tool, please refer to the `usage` printout below:

```
Usage: ./oesign sign --enclave-image [-e] enclave_image --config-file [-c] config_file --key-file [-k] key_file

Where:
    enclave_image -- path of an enclave image file
    config_file -- configuration file containing enclave properties
    key_file -- private key file used to digitally sign the image

Description:
    This utility (1) injects runtime properties into an enclave image and
    (2) digitally signs that image.

    The properties are read from the <ConfigFile>. They override any
    properties that were already defined inside the enclave image through
    use of the OE_SET_ENCLAVE_SGX macro. These properties include:

        Debug - whether enclave debug mode should be enabled (1) or not (0)
        ProductID - the product identified number
        SecurityVersion - the security version number
        NumHeapPages - the number of heap pages for this enclave
        NumStackPages - the number of stack pages for this enclave
        NumTCS - the number of thread control structures for this enclave

    The configuration file contains simple NAME=VALUE entries. For example:

        Debug=1
        NumHeapPages=1024

    The key is read from <KeyFile> and contains a private RSA key in PEM
    format. The keyfile must contain the following header.

        -----BEGIN RSA PRIVATE KEY-----

    The resulting image is written to <EnclaveImage>.signed
```

## oesign dump

The oesign tool can also print information about a specified signed enclave image. Please refer to the usage below for how to do this:

```
Usage: ./oesign dump --enclave-image [-e] enclave_image

Where:
    enclave_image -- path of an enclave image file

Description:
    This option dumps the oeinfo and signature information of an enclave
```
