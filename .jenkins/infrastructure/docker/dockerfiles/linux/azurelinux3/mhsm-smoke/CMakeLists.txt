# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.13)
project(openenclave_mhsm_smoke LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(MHSM_REQUIRED_OE_TARGETS
    openenclave::oecryptoopenssl_3
    openenclave::oeedger8r
    openenclave::oeenclave
    openenclave::oehost
    openenclave::oelibc
    openenclave::oelibcxx
    openenclave::oesign)

foreach (target IN LISTS MHSM_REQUIRED_OE_TARGETS)
  if (NOT TARGET ${target})
    message(FATAL_ERROR "Required MHSM Open Enclave target is missing: ${target}")
  endif ()
endforeach ()