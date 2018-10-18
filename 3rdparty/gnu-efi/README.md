gnu-efi:
========

This directory contains Intel's BSD-licensed gnu-efi implementation.
Open Enclave only uses a single header from the source tree:

```
./gnu-efi/gnu-efi-3.0/inc/x86_64/pe.h
```

This header defines headers for the PE format. Open Enclave uses these
definitions on Linux to compile the PE image loader.
