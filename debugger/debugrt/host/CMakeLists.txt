# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX)
  add_library(oedebugrt OBJECT
    host.c)

  target_compile_options(oedebugrt PRIVATE
    -fPIC)

  install(TARGETS oedebugrt EXPORT openenclave-targets)
else()
  #TODO: Switch to DLL on Windows
  add_library(oedebugrt OBJECT
    host.c)
  install(TARGETS oedebugrt EXPORT openenclave-targets
    # TODO:Switch to DLL on Windows
    # ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()

target_include_directories(oedebugrt PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
