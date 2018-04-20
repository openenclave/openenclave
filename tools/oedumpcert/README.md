oedumpcert
==========

This directory contains the **oedumpcert** utility which dumps the contents
of a PEM certificate. It is mainly a test utility for the Open Enclave crypto
function.

Use the **openssl** utility to get a more complete dump. For example:

```
# openssl x509 -in cert.pem -text -noout
```
