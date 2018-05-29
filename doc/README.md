doc
===

This directory contains all documentation for the Open Enclave SDK.

[Contributing to Open Enclave](Contributing.md)
------------------------------

This document discusses the guidelines and expectations for contributing to the
Open Enclave SDK.

[Development Guide](DevelopmentGuide.md)
-------------------

This document provides guidelines for developing code in the Open Enclave repo,
such as style guides and development processes.

[Getting Started with Open Enclave](GettingStarted.md)
-----------------------------------

This document explains how to build and use the Open Enclave SDK.

[Getting Started on Windows](GettingStarted.Windows.md)
-----------------------------------

This document explains how to use the experimental support for building host
applications on Windows that can use enclaves created with the Open Enclave
SDK.

[Open Enclave Design Overview](DesignOverview.pdf)
------------------------------

This document describes the architecture and design of the Open Enclave SDK.
It is maintained as a Word document [DesignOverview.docx](DesignOverview.docx).
The PDF version is generated after updates to the DOCX using the Microsoft
Print to PDF option in Word. Both the PDF and DOCX should be committed when the
design overview is updated.

[Open Enclave Function Reference](refman/md/index.md)
---------------------------------

The API reference for the Open Enclave SDK is generated using Doxygen in the
`refman` subfolder. For more details on how to update the API reference using
Doxygen, refer to [Using Doxygen in Open Enclave](refman/doxygen-howto.md).

### Converting MD to HMTL

While we maintain most documents in as Markdown for ease of updating,
developers who wish to read them in HTML format can convert them easily.
For example, to convert GettingStarted.md into HTML:

```
$ sudo apt install python-pip
$ pip install grip
$ grip GettingStarted.md --export GettingStarted.html
```

[Open Enclave Support for libc](LibcSupport.md)
-------------------------------
This document describes the C library functionality supported inside an enclave
as provided by oelibc.

[Open Enclave Support for libcxx](LibcxxSupport.md)
---------------------------------
This document describes the C++ library functionality supported inside an
enclave as provided by oelibcxx.

[Open Enclave Support for mbedtls](MbedtlsSupport.md)
---------------------------------_
This document describes the mbedtls library functionality supported inside an
enclave as provided by 3rdparty/mbedtls.
