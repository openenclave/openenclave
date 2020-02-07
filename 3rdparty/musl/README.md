# Musl libc and libc-test projects

This directory contains the musl libc library and acompanying libc-test test
suite.

See `./update.make` for specific information regarding the source and version
of these projects.

## musl libc:

This directory contains **musl libc**

Typing **make** installs the source tree under the build directory and
applies patches to it. Nothing is built though, as building is performed
from the **libc** directory.

## libc-test:

libc-test is a generic libc testing framework.

Building for OE tests is performed from tests/libc/CMakeLists.txt.
