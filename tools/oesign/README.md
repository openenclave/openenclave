# oesign - HOWTO

## oesign sign

The `oesign` tool should be used with the subcommand `sign` to sign enclaves. The samples show how a developer should use this tool to sign their enclave images before using them. Please refer to how one of the samples uses this tool here: https://github.com/openenclave/openenclave/blob/master/samples/helloworld/enclave/Makefile

All enclave images should be signed before they are used in production.

To understand the full CLI of this tool, please refer to the `usage` printout below:

```
Usage: output/bin/oesign sign -e ENCLAVE_IMAGE [-c CONFIG_FILE] [SIGN_OPTIONS...]
Where:
    ENCLAVE_IMAGE -- path of an enclave image file
    CONFIG_FILE -- configuration file containing enclave properties

Description:
    This command (1) injects runtime properties into an enclave image
    and (2) digitally signs that image.

    The properties are read from the CONFIG_FILE. They override any
    properties that were already defined inside the enclave image
    through use of OE_SET_ENCLAVE_SGX or OE_SET_ENCLAVE_SGX2 macros.
    If a property is not explicitly set, the default values override
    the definitions set by SET_OE_ENCLAVE_SGX(2) macros.
    These properties include:

        Debug - whether debug mode should be enabled (1) or not (0) in enclave
        (default: 0)
        ProductID - the product identified number
        SecurityVersion - the security version number
        NumHeapPages - the number of heap pages for this enclave
        NumStackPages - the number of stack pages for this enclave
        NumTCS - the number of thread control structures for this enclave
        ExtendedProductID - a 128-bit globally unique identifier for the
        enclave if the 16-bit ProductID proves too restrictive  (SGX2 feature).
        Defaults to zero value if property is not included in CONFIG_FILE.
        FamilyID - product family identity to group different enclaves
        under a common identity (SGX2 feature). Defaults to zero value if property
        is not included in CONFIG_FILE.
        CapturePFGPExceptions - whether in-enclave exception handler should
        be enabled (1) or not (0) to capture #PF and #GP exceptions
        (SGX2 feature, default: 0)
        CreateZeroBaseEnclave - whether the enclave creation should be
        enabled (1) or not (0) with base address 0x0 (default: 0).
        StartAddress -  the enclave image address when CreateZeroBaseEnclave=1.
        The value should be a power of two and greater than
        /proc/sys/vm/mmap_min_addr

    NOTE: If neither ExtendedProductID nor FamilyID is set, Key Separation
    and Sharing (KSS) is disabled by default.

    The configuration file contains simple NAME=VALUE entries. For example:

        Debug=1
        NumHeapPages=1024

    If specified, the key read from KEY_FILE and contains a private RSA key in PEM
    format. The keyfile must contain the following header:

        -----BEGIN RSA PRIVATE KEY-----

    The resulting image is written to ENCLAVE_IMAGE.signed
```

## oesign dump

The oesign tool can also print information about a specified signed enclave image. Please refer to the usage below for how to do this:

```
Usage: ./output/bin/oesign dump {--enclave-image | -e} ENCLAVE_IMAGE

Where:
    ENCLAVE_IMAGE -- path of an enclave image file

Description:
    This option dumps the oeinfo and signature information of an enclave
```
