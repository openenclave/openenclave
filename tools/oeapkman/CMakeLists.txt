# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(SCRIPT ${PROJECT_SOURCE_DIR}/tools/oeapkman/oeapkman)
add_executable(oeapkman IMPORTED GLOBAL)
set_target_properties(oeapkman PROPERTIES IMPORTED_LOCATION ${SCRIPT}
                                          ROOT "$ENV{HOME}/.oeapkman/alpine-fs")

install(PROGRAMS oeapkman DESTINATION ${CMAKE_INSTALL_BINDIR})
