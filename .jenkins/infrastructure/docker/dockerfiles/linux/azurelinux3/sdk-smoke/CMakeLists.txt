# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.13)
project(openenclave_sdk_smoke LANGUAGES C CXX)

find_package(OpenEnclave CONFIG REQUIRED)

set(REQUIRED_OE_TARGETS
    openenclave::oecryptoopenssl_3
    openenclave::oeedger8r
    openenclave::oeenclave
    openenclave::oehost
    openenclave::oelibc
    openenclave::oelibcxx
    openenclave::oesign)

foreach (target IN LISTS REQUIRED_OE_TARGETS)
  if (NOT TARGET ${target})
    message(FATAL_ERROR "Required Open Enclave target is missing: ${target}")
  endif ()
endforeach ()
