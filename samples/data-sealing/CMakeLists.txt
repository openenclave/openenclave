# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

# If the CC environment variable has been specified or if the CMAKE_C_COMPILER
# cmake variable has been passed to cmake, use the C compiler that has been
# specified. Otherwise, prefer clang. Same for C++ compiler.
# This must be done before the `project` command.
if (UNIX)
  if (NOT DEFINED ENV{CC} AND NOT DEFINED CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang-10 clang)
  endif ()
  if (NOT DEFINED ENV{CXX} AND NOT DEFINED CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang++-10 clang++)
  endif ()
endif ()

project("Data Sealing Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)
set(OE_CRYPTO_LIB
    mbedtls
    CACHE STRING "Crypto library used by enclaves.")

function (add_edl edl_file)
  cmake_parse_arguments(arg "" "TRUSTED;UNTRUSTED" "" ${ARGN})
  if (arg_UNPARSED_ARGUMENTS)
    message(
      FATAL_ERROR
        "add_edl: Unrecogized arguments -- \"${arg_UNPARSED_ARGUMENTS}\"")
  endif ()

  set(opts --search-path ${OE_INCLUDEDIR} --search-path
           ${OE_INCLUDEDIR}/openenclave/edl/sgx)
  if (NOT arg_TRUSTED AND NOT arg_UNTRUSTED)
    set(arg_TRUSTED ".")
    set(arg_UNTRUSTED ".")
  elseif (arg_TRUSTED AND NOT arg_UNTRUSTED)
    list(APPEND opts --trusted)
  elseif (NOT arg_TRUSTED AND arg_UNTRUSTED)
    list(APPEND opts --untrusted)
  endif ()

  get_filename_component(basename ${edl_file} NAME_WE)

  if (arg_TRUSTED)
    list(APPEND opts --trusted-dir ${arg_TRUSTED})
    set(tbase "${arg_TRUSTED}/${basename}_")
    list(APPEND outs ${tbase}t.c ${tbase}t.h ${tbase}args.h)
  endif ()

  if (arg_UNTRUSTED)
    list(APPEND opts --untrusted-dir ${arg_UNTRUSTED})
    set(ubase "${arg_UNTRUSTED}/${basename}_")
    list(APPEND outs ${ubase}u.c ${ubase}u.h ${ubase}args.h)
  endif ()

  if (NOT IS_ABSOLUTE edl_file)
    string(PREPEND edl_file ${CMAKE_CURRENT_SOURCE_DIR}/)
  endif ()

  list(REMOVE_DUPLICATES outs)
  add_custom_command(
    OUTPUT ${outs}
    DEPENDS ${edl_file}
    COMMAND openenclave::oeedger8r ${opts} ${edl_file})
endfunction ()

add_subdirectory(common)
add_subdirectory(enclave_a_v1)
add_subdirectory(enclave_a_v2)
add_subdirectory(enclave_b)
add_subdirectory(host)

# Generate keys A and B
foreach (k a b)
  set(pem_file private_${k}.pem)
  add_custom_command(OUTPUT ${pem_file} COMMAND openssl genrsa -out ${pem_file}
                                                -3 3072)
endforeach ()

# Sign enclaves
foreach (e a_v1 a_v2 b)
  string(REGEX MATCH "^[a-z]" k ${e})
  set(enclave enclave_${e})
  add_custom_command(
    OUTPUT ${enclave}/${enclave}.signed
    DEPENDS ${enclave} ${enclave}/data-sealing.conf private_${k}.pem
    COMMAND
      openenclave::oesign sign -e $<TARGET_FILE:${enclave}> -c
      ${CMAKE_SOURCE_DIR}/${enclave}/data-sealing.conf -k private_${k}.pem)
endforeach ()

add_custom_target(
  sign ALL DEPENDS enclave_a_v1/enclave_a_v1.signed
                   enclave_a_v2/enclave_a_v2.signed enclave_b/enclave_b.signed)

add_custom_target(
  run
  DEPENDS data-sealing_host sign
  COMMAND
    data-sealing_host ${CMAKE_BINARY_DIR}/enclave_a_v1/enclave_a_v1.signed
    ${CMAKE_BINARY_DIR}/enclave_a_v2/enclave_a_v2.signed
    ${CMAKE_BINARY_DIR}/enclave_b/enclave_b.signed)
