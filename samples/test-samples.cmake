# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# This script requires the variables SOURCE_DIR, BUILD_DIR,
# COMPILER_SUPPORTS_SNMALLOC, USE_DEBUG_MALLOC and PREFIX_DIR to be defined:
#
#     cmake -DSOURCE_DIR=~/openenclave \
#           -DBUILD_DIR=~/openenclave/build
#           -DPREFIX_DIR=/opt/openenclave \
#           -P ~/openenclave/samples/test-samples.cmake

# Determine whether DCAP quote provider libraries are available in the system.
# Delete the file and create afresh so that DCAP libraries are checked
# every time samples test is run.
file(REMOVE check_quote_provider/CMakeLists.txt)
configure_file(${SOURCE_DIR}/check_quote_provider.cmake
               check_quote_provider/CMakeLists.txt COPYONLY)

# When executed in script mode (i.e -P), find_library command is not supported.
# Therefore run cmake on the above created CMakeLists.txt. It internally
# invokes find_library and will error out if sgx_dcap_ql is not found.
execute_process(
  COMMAND ${CMAKE_COMMAND} .
  WORKING_DIRECTORY check_quote_provider
  OUTPUT_QUIET ERROR_QUIET
  RESULT_VARIABLE COMMAND_EXIT_CODE)

if (COMMAND_EXIT_CODE EQUAL 0)
  set(HAS_QUOTE_PROVIDER on)
  message(
    STATUS
      "System has DCAP libraries. Attestation based samples will be tested.")
else ()
  set(HAS_QUOTE_PROVIDER off)
  message(
    WARNING
      "System does not have DCAP libraries. Attestation based samples will NOT be tested."
  )
endif ()

# Set SAMPLES_LIST so that helloworld becomes the first if BUILD_ENCLAVES=ON.
if (BUILD_ENCLAVES)
  set(SAMPLES_LIST debugmalloc file-encryptor helloworld log_callback
                   switchless)
  set(CRYPTO_LIB_LIST openssl_3 openssl_3 openssl_3 openssl_3 openssl_3)
  # Debug malloc will set allocated memory to a fixed pattern.
  # Hence do not enable pluggable_allocator test under USE_DEBUG_MALLOC.
  if (COMPILER_SUPPORTS_SNMALLOC AND NOT USE_DEBUG_MALLOC)
    list(APPEND SAMPLES_LIST pluggable_allocator)
    list(APPEND CRYPTO_LIB_LIST openssl_3)
  endif ()

  if (UNIX)
    list(APPEND SAMPLES_LIST apkman)
    list(APPEND CRYPTO_LIB_LIST openssl_3)
  endif ()
endif ()

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
  if (BUILD_ENCLAVES)
    list(APPEND SAMPLES_LIST data-sealing)
    list(APPEND CRYPTO_LIB_LIST openssl_3)

    # These tests can only run with SGX-FLC, meaning they were built
    # against SGX.
    if (HAS_QUOTE_PROVIDER)
      list(
        APPEND
        SAMPLES_LIST
        attested_tls
        attested_tls
        attested_tls
        attested_tls
        attestation
        file-encryptor
        file-encryptor)
      list(
        APPEND
        CRYPTO_LIB_LIST
        openssl
        openssl_symcrypt_fips
        openssl_3
        openssl_3_symcrypt_prov_fips
        openssl_3
        openssl
        openssl_3)
    endif ()
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

list(LENGTH SAMPLES_LIST len)
math(EXPR len "${len} - 1")
foreach (i RANGE ${len})
  if (NOT SAMPLES_LIST)
    break()
  endif ()

  list(GET SAMPLES_LIST ${i} SAMPLE)
  list(GET CRYPTO_LIB_LIST ${i} CRYPTO_LIB)

  set(SAMPLE_BUILD_DIR ${BUILD_DIR}/samples/${SAMPLE})
  set(SAMPLE_SOURCE_DIR ${INSTALL_DIR}/share/openenclave/samples/${SAMPLE})
  set(CMAKE_CRYPTO_LIB_DEFINE "")
  set(MAKE_CRYPTO_LIB_DEFINE "")

  if (CRYPTO_LIB STREQUAL "openssl")
    set(SAMPLE_BUILD_DIR "${SAMPLE_BUILD_DIR}_openssl")
    set(CMAKE_CRYPTO_LIB_DEFINE "-DOE_CRYPTO_LIB=openssl")
    set(MAKE_CRYPTO_LIB_DEFINE "OE_CRYPTO_LIB=openssl")
  elseif (CRYPTO_LIB STREQUAL "openssl_symcrypt_fips")
    set(SAMPLE_BUILD_DIR "${SAMPLE_BUILD_DIR}_openssl_symcrypt_fips")
    set(CMAKE_CRYPTO_LIB_DEFINE "-DOE_CRYPTO_LIB=openssl_symcrypt_fips")
    set(MAKE_CRYPTO_LIB_DEFINE "OE_CRYPTO_LIB=openssl_symcrypt_fips")
  elseif (CRYPTO_LIB STREQUAL "openssl_3")
    set(SAMPLE_BUILD_DIR "${SAMPLE_BUILD_DIR}_openssl_3")
    set(CMAKE_CRYPTO_LIB_DEFINE "-DOE_CRYPTO_LIB=openssl_3")
    set(MAKE_CRYPTO_LIB_DEFINE "OE_CRYPTO_LIB=openssl_3")
  elseif (CRYPTO_LIB STREQUAL "openssl_3_symcrypt_prov_fips")
    set(SAMPLE_BUILD_DIR "${SAMPLE_BUILD_DIR}_openssl_3_symcrypt_prov_fips")
    set(CMAKE_CRYPTO_LIB_DEFINE "-DOE_CRYPTO_LIB=openssl_3_symcrypt_prov_fips")
    set(MAKE_CRYPTO_LIB_DEFINE "OE_CRYPTO_LIB=openssl_3_symcrypt_prov_fips")
  endif ()

  execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory
                          ${SAMPLE_BUILD_DIR})

  # Configure, build, and run the installed sample with CMake.
  if (WIN32)
    execute_process(
      COMMAND
        ${CMAKE_COMMAND}
        -DCMAKE_PREFIX_PATH=${INSTALL_DIR}/lib/openenclave/cmake -G Ninja
        -DNUGET_PACKAGE_PATH=${NUGET_PACKAGE_PATH} ${CMAKE_CRYPTO_LIB_DEFINE}
        ${SAMPLE_SOURCE_DIR}
      WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})
  else ()
    execute_process(
      COMMAND ${CMAKE_COMMAND} -DCMAKE_PREFIX_PATH=${INSTALL_DIR}
              ${CMAKE_CRYPTO_LIB_DEFINE} ${SAMPLE_SOURCE_DIR}
      WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})
  endif ()

  execute_process(COMMAND ${CMAKE_COMMAND} --build ${SOURCE_DIR}/${SAMPLE}
                  WORKING_DIRECTORY ${SAMPLE_BUILD_DIR})

  if (NOT SIMULATION)
    # Build with the CMake package
    message(
      STATUS "Samples test '${SAMPLE}-${CRYPTO_LIB}' with CMake running...")
    execute_process(COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR}
                            --target run RESULT_VARIABLE TEST_RESULT)

    if (TEST_RESULT)
      message(
        WARNING "Samples test '${SAMPLE}-${CRYPTO_LIB}' with CMake failed!")
      set(ALL_TEST_RESULT 1)
    else ()
      message(
        STATUS "Samples test '${SAMPLE}-${CRYPTO_LIB}' with CMake passed!")
    endif ()

    if (UNIX)
      # Build with pkg-config if not running on Windows.
      message(
        STATUS
          "Samples test '${SAMPLE}-${CRYPTO_LIB}' with pkg-config running...")
      execute_process(
        COMMAND
          ${CMAKE_COMMAND} -E env PATH=${INSTALL_DIR}/bin:$ENV{PATH}
          PKG_CONFIG_PATH=${INSTALL_DIR}/share/pkgconfig/ make -C
          ${SAMPLE_SOURCE_DIR} clean build ${MAKE_CRYPTO_LIB_DEFINE} run
        RESULT_VARIABLE TEST_RESULT)
      if (TEST_RESULT)
        message(
          WARNING
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' with pkg-config failed!")
        set(ALL_TEST_RESULT 1)
      else ()
        message(
          STATUS
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' with pkg-config passed!")
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
        STATUS
          "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with CMake running..."
      )
      execute_process(
        COMMAND ${CMAKE_COMMAND} --build ${SAMPLE_BUILD_DIR} --target simulate
        RESULT_VARIABLE TEST_SIMULATE_RESULT)
      if (TEST_SIMULATE_RESULT)
        message(
          WARNING
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with CMake failed!"
        )
        set(ALL_TEST_RESULT 1)
      else ()
        message(
          STATUS
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with CMake passed!"
        )
      endif ()

      # Build with pkg-config
      message(
        STATUS
          "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with pkg-config running..."
      )
      message(WARNING "PKG_CONFIG_PATH=${INSTALL_DIR}")
      execute_process(
        COMMAND
          ${CMAKE_COMMAND} -E env PATH=${INSTALL_DIR}/bin:$ENV{PATH}
          PKG_CONFIG_PATH=${INSTALL_DIR}/share/pkgconfig make -C
          ${SAMPLE_SOURCE_DIR} clean build ${MAKE_CRYPTO_LIB_DEFINE} simulate
        RESULT_VARIABLE TEST_SIMULATE_RESULT)
      if (TEST_SIMULATE_RESULT)
        message(
          WARNING
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with pkg-config failed!"
        )
        set(TEST_SIMULATE_RESULT 1)
      else ()
        message(
          STATUS
            "Samples test '${SAMPLE}-${CRYPTO_LIB}' in simulation with pkg-config passed!"
        )
      endif ()
    endif ()
  endif ()

endforeach ()

if (${ALL_TEST_RESULT})
  message(
    FATAL_ERROR
      "One of the samples failed while testing it. Please check the log!")
endif ()
