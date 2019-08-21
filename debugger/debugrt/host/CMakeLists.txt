# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

if (UNIX)
  add_library(oedebugrt OBJECT
    host.c)

  target_compile_options(oedebugrt PRIVATE
    -fPIC)

  install(TARGETS oedebugrt EXPORT openenclave-targets)
else()
  add_library(oedebugrt SHARED
    host.c)

  target_compile_definitions(oedebugrt PRIVATE
    OE_BUILDING_DEBUGRT_SHARED_LIBRARY)
  
  install(TARGETS oedebugrt EXPORT openenclave-targets
    # TODO:Determine DLL install location on Windows
    ARCHIVE DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

target_include_directories(oedebugrt PRIVATE
  ${PROJECT_SOURCE_DIR}/include)
