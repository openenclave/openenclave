libc tests
==========

This directory runs the MUSL libc unit tests. It reads **tests.cmake** and 
generates a wrapper (in the build directory) for each of the tests in this file.

All unit tests are all listed in **tests.cmake** in the following sections:

* Supported -- unit tests that work.
* Broken -- unit tests that are broken.
* Unsupported -- unit tests that are unsupported.

Tests determined to be unsupportable should be moved to the broken section.
