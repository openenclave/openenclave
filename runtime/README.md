runtime
=======

This directory contains the sources for the oeruntime library, which implements
the enclave extrasi, which depend on mbedtls and oelibc. The main parts include:

- Certificate management ([cert.c](cert.c))

- EC key management ([ec.c](ec.c))

- RSA key management ([rsa.c](rsa.c))

- Entropy ([random.c](random.c))

- SHA hash management ([sha.c](sha.c))

