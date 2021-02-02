# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_edl(../datasealing.edl TRUSTED .)

# Create a library common to each of our three enclaves.
add_library(common OBJECT dispatcher.cpp
                          ${CMAKE_CURRENT_BINARY_DIR}/datasealing_t.c)
target_compile_definitions(common PUBLIC OE_API_VERSION=2)

add_custom_target(
  print_seal_plugin ALL
  COMMAND ${CMAKE_COMMAND} -E echo
          "** Seal Plugin: $<TARGET_OBJECTS:openenclave::oeseal_gcmaes>")

target_link_libraries(
  common
  INTERFACE $<TARGET_OBJECTS:openenclave::oeseal_gcmaes>
  PUBLIC openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
         openenclave::oelibcxx)

if (WIN32)
  maybe_build_using_clangw(common)
endif ()

target_include_directories(common PUBLIC ${CMAKE_SOURCE_DIR}
                                         ${CMAKE_BINARY_DIR})
