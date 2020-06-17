# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (UNIX)
  add_library(oedebugrt OBJECT host.c)

  target_compile_options(oedebugrt PRIVATE -fPIC)

  install(TARGETS oedebugrt EXPORT openenclave-targets)
else ()
  add_library(oedebugrt SHARED host.c)

  target_compile_definitions(oedebugrt
                             PRIVATE OE_BUILDING_DEBUGRT_SHARED_LIBRARY)

  # oedebugrt must itself have debug symbols for WinDbg to support OE
  # debugging. Therefore oedebugrt must be compiled with /Zi and oedebugrt.pdb
  # must be installed alongside oedebugrt.dll.
  # Note: VS Debugger does not have this requirement. This WinDbg requirement
  # is temporary.
  set_target_properties(
    oedebugrt PROPERTIES COMPILE_FLAGS "/Zi" # Compile with debug information
                         LINK_FLAGS "/INCREMENTAL:NO /DEBUG /OPT:REF /OPT:ICF"
  )# Create pdb
  install(FILES $<TARGET_PDB_FILE:oedebugrt>
          DESTINATION ${CMAKE_INSTALL_BINDIR})
  install(
    TARGETS oedebugrt
    EXPORT openenclave-targets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif ()

target_include_directories(oedebugrt PRIVATE ${PROJECT_SOURCE_DIR}/include)
