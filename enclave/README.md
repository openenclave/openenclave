enclave
=======

This directory contains the sources for the oeenclave library, which implements
the enclave extras, which depend on mbedtls and oelibc. The main parts include:

- Certificate management ([cert.c](cert.c))

- EC key management ([ec.c](ec.c))

- RSA key management ([rsa.c](rsa.c))

- SHA hash management ([sha.c](sha.c))
