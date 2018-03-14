Example Certificate Chain Generation
====================================

This directory contains a makefile for generating the following chain of
certificates (from CA to leaf).

```
root.crt
intermediate.crt
leaf.crt
```

To generate all certificates (as well as all private keys), type the following.

```
make
```

To verify the certificate chain, type the following.

```
make verify
```
