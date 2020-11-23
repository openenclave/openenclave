
This directory tests the usage of enclave properties, which may be defined
in one of two ways:

- Using the OE_SET_ENCLAVE_SGX macro (for unsigned debug enclaves)
- Using the OESIGN tool (for signed enclaves)

In both cases, the enclave properties are written to a special enclave
properties section (.oeinfo) within the enclave image.

The enclave loader is able to load unsigned debug images, by use of the
OE_SET_ENCLAVE_SGX macro.

The propshost program tests both of these scenarios. It is run once for 
the unsigned case and once for the signed case as follows.

```
# ./host/propshost ./enc/propsenc unsigned
# ./host/propshost ./enc/propsenc.signed signed
```

These tests check that the enclave properties contain the expected values.
