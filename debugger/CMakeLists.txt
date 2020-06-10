# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  add_subdirectory(ptraceLib)
  add_subdirectory(pythonExtension)

  # Copy oegdb to build/output/bin so that it can be used
  # for debugging enclaves built as part of OE SDK.
  file(COPY oegdb DESTINATION ${OE_BINDIR})

  install(PROGRAMS oegdb DESTINATION ${CMAKE_INSTALL_BINDIR})

endif ()

# debugrt is built on all SGX platforms
add_subdirectory(debugrt)
