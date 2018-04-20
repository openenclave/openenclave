oedumpcert
==========

This directory contains the **oedumpcert** utility which dumps the contents
of a PEM certificate or PEM certificate chain. It is intended only as a test 
utility for the Open Enclave crypto feature. Use the **openssl** utility to 
get a more complete dump. For example:

```
# openssl x509 -in cert.pem -text -noout
```

The **oedumpcert** utility takes a single command-line argument as shown below.

```
# oedumpcert cert.pem
OE_Cert
{
    subject=/CN=Test Leaf/ST=Texas/C=US/O=Microsoft/OU=OpenEnclave
    ...
    RSAPublicKey
    {
        numModulusBytes=256
        numModulusBits=2048
        numExponentBytes=3
        numExponentBits=17
        ...
    }
    ...
}
```
