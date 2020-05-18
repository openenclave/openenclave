# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
option(ENABLE_REFMAN "Enable Doxygen reference manual generation" ON)

if (ENABLE_REFMAN)
  find_package(Doxygen)

  if (NOT DOXYGEN_FOUND)
    message(
      FATAL_ERROR
        "Doxygen not found! Skip generation with '-DENABLE_REFMAN=OFF'")
  endif ()

  set(DOXYGEN_PROJECT_NAME "Open Enclave")
  set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "MainPage.md")
  set(DOXYGEN_OUTPUT_DIRECTORY "${OE_DOCDIR}/openenclave")
  set(DOXYGEN_RECURSIVE NO) # CMake enables this by default.
  # While Doxygen would automatically strip the working directory, we
  # have to specify it because we have another directory to strip.
  set(DOXYGEN_STRIP_FROM_PATH
      "${PROJECT_SOURCE_DIR}/include/openenclave/;${PROJECT_SOURCE_DIR}/docs/refman"
  )

  # Allow @experimental to be used in headers to mark an API as experimental and add it to a list of
  # experimental APIs.
  # Also allow @advanced to be used in headers to mark an API as advanced and add it to a list of
  # advanced APIs.
  set(DOXYGEN_ALIASES
      "experimental = \\xrefitem experimental \\\"This feature is marked as experimental\\\" \\\"Experimental List\\\""
      "experimental{1} = \\xrefitem experimental \\\"Experimental\\\" \\\"Experimental List\\\" \\1"
      "advanced = \\xrefitem advanced \\\"This feature is marked as advanced and is not intended for use by apps\\\" \\\"Advanced List\\\""
  )

  # NOTE: These were set to their non-default values in the existing
  # configuration file, so that configuration has been copied here.
  # However, they may or may not be desired.
  set(DOXYGEN_JAVADOC_AUTOBRIEF YES)
  set(DOXYGEN_QT_AUTOBRIEF YES)
  set(DOXYGEN_SEPARATE_MEMBER_PAGES YES)
  set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
  set(DOXYGEN_GENERATE_LATEX NO)
  set(DOXYGEN_MACRO_EXPANSION YES)
  set(DOXYGEN_EXPAND_ONLY_PREDEF YES)
  set(DOXYGEN_PREDEFINED "=OE_ALIGNED(x)=;OE_EXTERNC_BEGIN=")

  doxygen_add_docs(
    doxygen
    # This list of files is explicit because we disable recursion.
    enclave.h
    host.h
    bits/properties.h
    bits/report.h
    bits/result.h
    bits/types.h
    bits/exception.h
    bits/module.h
    ../../docs/refman/MainPage.md
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/include/openenclave/
    COMMENT "Generating refman HTML documentation")
endif ()
