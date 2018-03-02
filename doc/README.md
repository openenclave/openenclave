doc
===

This directory contains all documentation for the Open Enclave SDK.

[Getting Started with Open Enclave](GettingStarted.md)
-----------------------------------

This document explains how to build and use the Open Enclave SDK. It is
maintained as Markdown and can be updated in plaintext, and developers can
convert it to a format of their choice. For example, to convert MD into HTML:

```
$ sudo apt install python-pip
$ pip install grip
$ grip GettingStarted.md --export GettingStarted.html
```

[Getting Started on Windows](GettingStarted.windows.md)
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
refman/ subfolder. For more details on how to update the API reference using
Doxygen, refer to [Using Doxygen in Open Enclave](doxygen-howto.md).