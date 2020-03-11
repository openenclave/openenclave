# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
#
# Set default paths
# TODO: See #757: Actually use GNUInstallDirs and don't hard-code our
# own paths.

# Set the default install prefix for Open Enclave. One may override this value
# with the cmake command. For example:
#
#     $ cmake -DCMAKE_INSTALL_PREFIX=/opt/myplace ..
#
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  if (WIN32)
    set(CMAKE_INSTALL_PREFIX
      "./openenclave" CACHE PATH "default install prefix" FORCE)
  else ()
    set(CMAKE_INSTALL_PREFIX
      "/opt/openenclave" CACHE PATH "default install prefix" FORCE)
  endif ()
endif()

include(GNUInstallDirs)
set(OE_OUTPUT_DIR ${PROJECT_BINARY_DIR}/output CACHE INTERNAL "Path to the intermittent collector tree")
set(OE_BINDIR ${OE_OUTPUT_DIR}/bin CACHE INTERNAL "Binary collector")
set(OE_DATADIR ${OE_OUTPUT_DIR}/share CACHE INTERNAL "Data collector root")
set(OE_DOCDIR ${OE_OUTPUT_DIR}/share/doc CACHE INTERNAL "Doc collector root")
set(OE_INCDIR ${OE_OUTPUT_DIR}/include CACHE INTERNAL "Include collector")
set(OE_LIBDIR ${OE_OUTPUT_DIR}/lib CACHE INTERNAL "Library collector")

# Make directories for build systems (NMake) that don't automatically make them.
file(MAKE_DIRECTORY ${OE_BINDIR} ${OE_DATADIR} ${OE_DOCDIR} ${OE_DOCDIR} ${OE_INCDIR} ${OE_LIBDIR})

# Generate and install CMake export file for consumers using CMake
include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${PROJECT_SOURCE_DIR}/cmake/openenclave-config.cmake.in
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR CMAKE_INSTALL_DATADIR CMAKE_INSTALL_INCLUDEDIR)
write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
  COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_BINARY_DIR}/cmake/openenclave-config.cmake
  ${CMAKE_BINARY_DIR}/cmake/openenclave-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  COMPONENT OEHOSTVERIFY)
install(
  EXPORT openenclave-targets
  NAMESPACE openenclave::
  # Note that this is used in `openenclaverc` to set the path for
  # users of the SDK and so must remain consistent.
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  FILE openenclave-targets.cmake
  COMPONENT OEHOSTVERIFY)
install(
  FILES ${PROJECT_SOURCE_DIR}/cmake/sdk_cmake_targets_readme.md
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  RENAME README.md
  COMPONENT OEHOSTVERIFY)

# Generate and install the LVI mitigation package.
configure_package_config_file(
  ${PROJECT_SOURCE_DIR}/cmake/openenclave-lvi-mitigation-config.cmake.in
  ${CMAKE_BINARY_DIR}/cmake/openenclave-lvi-mitigation-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  PATH_VARS CMAKE_INSTALL_LIBDIR CMAKE_INSTALL_BINDIR CMAKE_INSTALL_DATADIR CMAKE_INSTALL_INCLUDEDIR)
write_basic_package_version_file(
  ${CMAKE_BINARY_DIR}/cmake/openenclave-lvi-mitigation-config-version.cmake
  COMPATIBILITY SameMajorVersion)
install(
  FILES ${CMAKE_BINARY_DIR}/cmake/openenclave-lvi-mitigation-config.cmake
  ${CMAKE_BINARY_DIR}/cmake/openenclave-lvi-mitigation-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/cmake
  COMPONENT OEHOSTVERIFY)

if (UNIX)
  # Generate the openenclaverc script.
  configure_file(
    ${PROJECT_SOURCE_DIR}/cmake/openenclaverc.in
    ${CMAKE_BINARY_DIR}/output/share/openenclave/openenclaverc
    @ONLY)

  # Install the openenclaverc script.
  install(FILES
    ${CMAKE_BINARY_DIR}/output/share/openenclave/openenclaverc
    DESTINATION
    "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DATADIR}/openenclave"
    COMPONENT OEHOSTVERIFY)
endif()
