# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Remote Host-side Enclave Verification Sample" LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_executable(host_verify host.c)

target_include_directories(host_verify PRIVATE)

target_link_libraries(host_verify openenclave::oehostverify)

add_custom_target(run DEPENDS host_verify)

if (NOT
    (EXISTS "sgx_cert_ec.der"
     OR EXISTS "sgx_cert_rsa.der"
     OR EXISTS "sgx_report.bin"))
  add_custom_target(
    run1
    DEPENDS host_verify
    COMMAND host_verify -h)
  add_dependencies(run run1)
else ()
  if (EXISTS "sgx_cert_ec.der")
    add_custom_target(
      run1
      DEPENDS host_verify
      COMMAND host_verify -c sgx_cert_ec.der)
    add_dependencies(run run1)
  endif ()
  if (EXISTS "sgx_cert_rsa.der")
    add_custom_target(
      run2
      DEPENDS host_verify
      COMMAND host_verify -c sgx_cert_rsa.der)
    add_dependencies(run run2)
  endif ()
  if (EXISTS "sgx_report.bin")
    add_custom_target(
      run3
      DEPENDS host_verify
      COMMAND host_verify -r sgx_report.bin)
    add_dependencies(run run3)
  endif ()
endif ()
