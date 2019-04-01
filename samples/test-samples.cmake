# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This script requires the variables SOURCE_DIR, BUILD_DIR, and
# PREFIX_DIR to be defined:
#
#     cmake -DSOURCE_DIR=~/openenclave -DBUILD_DIR=~/openenclave/build -DPREFIX_DIR=/opt/openenclave -P ~/openenclave/samples/test-samples.cmake

if ($ENV{OE_SIMULATION})
  message(WARNING "Running only sample simulation tests due to OE_SIMULATION=$ENV{OE_SIMULATION}!")
  # This is not a failure condition, so we return with a success status.
endif ()

# Install the SDK from current build to a known location in the build tree.
execute_process(COMMAND ${CMAKE_COMMAND} -E env DESTDIR=${BUILD_DIR}/install ${CMAKE_COMMAND} --build ${BUILD_DIR} --target install)

# The prefix is appended to the value given to DESTDIR, e.g. build/install/opt/openenclave/...
set(INSTALL_DIR ${BUILD_DIR}/install${PREFIX_DIR})

# A variable to know if all samples ran successfully
set(ALL_TEST_RESULT 0)

foreach (SAMPLE data-sealing file-encryptor helloworld local_attestation remote_attestation)
  set(SAMPLE_BUILD_DIR ${BUILD_DIR}/samples/${SAMPLE})
  set(SAMPLE_SOURCE_DIR ${INSTALL_DIR}/share/openenclave/samples/${SAMPLE})

  # Delete and re-create a clean build directory for the sample, used
  # as the working directory in the next steps.
  execute_process(COMMAND ${CMAKE_COMMAND} -E remove_directory ${SAMPLE_BUILD_DIR})
  execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory ${SAMPLE_BUILD_DIR})

  # Configure, build, and run the installed sample with CMake.
  execute_process(
    COMMAND ${CMAKE_COMMAND} -DCMAKE_PREFIX_PATH=${INSTALL_DIR} ${SAMPLE_SOURCE_DIR}
    WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build ${SOURCE_DIR}/${SAMPLE}
    WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})

  if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
    # Build with the CMake package
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR} --target run
      RESULT_VARIABLE TEST_RESULT)
    if (TEST_RESULT)
      message(WARNING "Samples test '${SAMPLE}' failed!")
      set(ALL_TEST_RESULT 1)
    endif ()

    # Build with pkg-config
    execute_process(
      COMMAND sh -c "PATH=${INSTALL_DIR}/bin:$PATH PKG_CONFIG_PATH=${BUILD_DIR}/pkgconfig OE_PREFIX=${INSTALL_DIR} make -C ${SAMPLE_SOURCE_DIR} clean build run"
      RESULT_VARIABLE TEST_RESULT)
      if (TEST_RESULT)
        message(WARNING "Samples test '${SAMPLE}' failed while building via Makefile!")
        set(ALL_TEST_RESULT 1)
    endif ()
  endif ()

  # The file-encryptor and helloworld are special cases which also
  # work under simulation, so we test that additional scenario here.
  if (${SAMPLE} MATCHES "(file-encryptor|helloworld)")
    # Build with the CMake package
    execute_process(
      COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR} --target simulate
      RESULT_VARIABLE TEST_SIMULATE_RESULT)
    if (TEST_SIMULATE_RESULT)
      message(WARNING "Samples test '${SAMPLE}' failed in simulation mode!")
      set(ALL_TEST_RESULT 1)
    endif ()

    # Build with pkg-config
    execute_process(
      COMMAND sh -c "PATH=${INSTALL_DIR}/bin:$PATH PKG_CONFIG_PATH=${BUILD_DIR}/pkgconfig OE_PREFIX=${INSTALL_DIR} make -C ${SAMPLE_SOURCE_DIR} clean build simulate"
      RESULT_VARIABLE TEST_SIMULATE_RESULT)
      if (TEST_SIMULATE_RESULT)
        message(WARNING "Samples test '${SAMPLE}' failed in simulation mode while building via Makefile!")
        set(TEST_SIMULATE_RESULT 1)
    endif ()
  endif ()

endforeach ()

if (${ALL_TEST_RESULT})
  message(FATAL_ERROR "One of the samples failed while testing it. Please check the log!")
endif ()
