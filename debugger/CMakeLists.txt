# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  set(PTRACE_LIBRARY ${OE_LIBDIR}/openenclave/debugger/liboe_ptrace.so)

  include(ExternalProject)

  ExternalProject_Add(
    ptraceLib
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ptraceLib
    BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/ptraceLib
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    BUILD_ALWAYS on
    TEST_BEFORE_INSTALL off
    INSTALL_COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/ptraceLib/libsgxptrace.so
                    ${PTRACE_LIBRARY}
    BUILD_BYPRODUCTS ${PTRACE_LIBRARY})

  install(PROGRAMS ${PTRACE_LIBRARY}
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/debugger)

  add_subdirectory(pythonExtension)

  # Copy oegdb to build/output/bin so that it can be used
  # for debugging enclaves built as part of OE SDK.
  file(COPY oegdb DESTINATION ${OE_BINDIR})

  install(PROGRAMS oegdb DESTINATION ${CMAKE_INSTALL_BINDIR})

endif ()

# debugrt is built on all SGX platforms
add_subdirectory(debugrt)
