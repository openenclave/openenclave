# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX)
  add_subdirectory(ptraceLib)
  add_subdirectory(pythonExtension)

  # Copy oegdb to build/output/bin so that it can be used
  # for debugging enclaves built as part of OE SDK.
  file(COPY oegdb DESTINATION ${OE_BINDIR})

  install(PROGRAMS oegdb DESTINATION ${CMAKE_INSTALL_BINDIR})

  # Copy and install a script with the deprecated name that emits a
  # warning about the rename and then replaces itself with `oegdb`.
  # TODO: Remove this in v0.7.0.
  file(COPY oe-gdb DESTINATION ${OE_BINDIR})

  install(PROGRAMS oe-gdb DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

#debugrt is built on all SGX platforms
add_subdirectory(debugrt)
