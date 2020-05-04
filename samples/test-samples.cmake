# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This script requires the variables SOURCE_DIR, BUILD_DIR, and
# PREFIX_DIR to be defined:
#
#     cmake -DHAS_QUOTE_PROVIDER=ON -DSOURCE_DIR=~/openenclave -DBUILD_DIR=~/openenclave/build -DPREFIX_DIR=/opt/openenclave -P ~/openenclave/samples/test-samples.cmake

set(SAMPLES_LIST helloworld file-encryptor switchless host_verify)

if ($ENV{OE_SIMULATION})
  message(
    WARNING
      "Running only sample simulation tests due to OE_SIMULATION=$ENV{OE_SIMULATION}!"
  )
  # Set because testing environment variables in CMake is annoying.
  set(SIMULATION ON)
else ()
  # All the other tests require that we are not running in simulation.

  # This sample can run on SGX, both with and without FLC, meaning
  # they can run even if they weren't built against SGX, because in
  # that cause they directly interface with the AESM service.
  list(APPEND SAMPLES_LIST data-sealing local_attestation)

  # These tests can only run with SGX-FLC, meaning they were built
  # against SGX.
  if (HAS_QUOTE_PROVIDER)
    list(APPEND SAMPLES_LIST remote_attestation)
    list(APPEND SAMPLES_LIST attested_tls)
  endif ()
endif ()

if (WIN32)
  # On Windows, DESTDIR is not supported by cmake for the install function.
  if (${PREFIX_DIR} MATCHES ^[a-zA-Z]:)
    #Absolute address
    set(INSTALL_DIR ${PREFIX_DIR})
  else ()
    #Relative address
    set(INSTALL_DIR ${BUILD_DIR}/${PREFIX_DIR})
  endif ()
  execute_process(COMMAND ${CMAKE_COMMAND} --build ${BUILD_DIR} --target
                          install)
else ()
  # The prefix is appended to the value given to DESTDIR, e.g. build/install/opt/openenclave/...
  set(INSTALL_DIR ${BUILD_DIR}/install/${PREFIX_DIR})
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env DESTDIR=${BUILD_DIR}/install
            ${CMAKE_COMMAND} --build ${BUILD_DIR} --target install)
endif ()

# A variable to know if all samples ran successfully
set(ALL_TEST_RESULT 0)

foreach (SAMPLE ${SAMPLES_LIST})
  set(SAMPLE_BUILD_DIR ${BUILD_DIR}/samples/${SAMPLE})
  set(SAMPLE_SOURCE_DIR ${INSTALL_DIR}/share/openenclave/samples/${SAMPLE})

  execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory
                          ${SAMPLE_BUILD_DIR})

  # Configure, build, and run the installed sample with CMake.
  if (WIN32)
    execute_process(
      COMMAND
        ${CMAKE_COMMAND}
        -DCMAKE_PREFIX_PATH=${INSTALL_DIR}/lib/openenclave/cmake -G Ninja
        -DNUGET_PACKAGE_PATH=${NUGET_PACKAGE_PATH}
        -DHAS_QUOTE_PROVIDER=${HAS_QUOTE_PROVIDER} ${SAMPLE_SOURCE_DIR}
      WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})
  else ()
    execute_process(
      COMMAND ${CMAKE_COMMAND} -DCMAKE_PREFIX_PATH=${INSTALL_DIR}
              ${SAMPLE_SOURCE_DIR} WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})
  endif ()

  execute_process(COMMAND ${CMAKE_COMMAND} --build ${SOURCE_DIR}/${SAMPLE}
                  WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})

  if (NOT SIMULATION)
    # Build with the CMake package
    message(STATUS "Samples test '${SAMPLE}' with CMake running...")
    execute_process(COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR}
                            --target run RESULT_VARIABLE TEST_RESULT)
    if (TEST_RESULT)
      message(WARNING "Samples test '${SAMPLE}' with CMake failed!")
      set(ALL_TEST_RESULT 1)
    else ()
      message(STATUS "Samples test '${SAMPLE}' with CMake passed!")
    endif ()

    if (UNIX)
      # Build with pkg-config if not running on Windows.
      message(STATUS "Samples test '${SAMPLE}' with pkg-config running...")
      execute_process(
        COMMAND
          ${CMAKE_COMMAND} -E env PATH=${INSTALL_DIR}/bin:$ENV{PATH}
          PKG_CONFIG_PATH=${INSTALL_DIR}/share/pkgconfig/ make -C
          ${SAMPLE_SOURCE_DIR} clean build run
        RESULT_VARIABLE TEST_RESULT)
      if (TEST_RESULT)
        message(WARNING "Samples test '${SAMPLE}' with pkg-config failed!")
        set(ALL_TEST_RESULT 1)
      else ()
        message(STATUS "Samples test '${SAMPLE}' with pkg-config passed!")
      endif ()
    endif ()
  endif ()

  # Simulation mode is not supported on Windows currently.
  if (UNIX)
    # The file-encryptor and helloworld are special cases which also
    # work under simulation, so we test that additional scenario here.
    if (${SAMPLE} MATCHES "(file-encryptor|helloworld)")
      # Build with the CMake package
      message(
        STATUS "Samples test '${SAMPLE}' in simulation with CMake running...")
      execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR} --target simulate
        RESULT_VARIABLE TEST_SIMULATE_RESULT)
      if (TEST_SIMULATE_RESULT)
        message(
          WARNING "Samples test '${SAMPLE}' in simulation with CMake failed!")
        set(ALL_TEST_RESULT 1)
      else ()
        message(
          STATUS "Samples test '${SAMPLE}' in simulation with CMake passed!")
      endif ()

      # Build with pkg-config
      message(
        STATUS
          "Samples test '${SAMPLE}' in simulation with pkg-config running...")
      message(WARNING "PKG_CONFIG_PATH=${INSTALL_DIR}")
      execute_process(
        COMMAND
          ${CMAKE_COMMAND} -E env PATH=${INSTALL_DIR}/bin:$ENV{PATH}
          PKG_CONFIG_PATH=${INSTALL_DIR}/share/pkgconfig make -C
          ${SAMPLE_SOURCE_DIR} clean build simulate
        RESULT_VARIABLE TEST_SIMULATE_RESULT)
      if (TEST_SIMULATE_RESULT)
        message(
          WARNING
            "Samples test '${SAMPLE}' in simulation with pkg-config failed!")
        set(TEST_SIMULATE_RESULT 1)
      else ()
        message(
          STATUS
            "Samples test '${SAMPLE}' in simulation with pkg-config passed!")
      endif ()
    endif ()
  endif ()

endforeach ()

if (${ALL_TEST_RESULT})
  message(
    FATAL_ERROR
      "One of the samples failed while testing it. Please check the log!")
endif ()
