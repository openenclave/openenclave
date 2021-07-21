# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

add_custom_command(
  OUTPUT sqlite_t.h sqlite_t.c sqlite_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/sqlite.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/sqlite.edl
    --search-path ${PROJECT_SOURCE_DIR}/include --search-path ${OE_INCLUDEDIR}
    --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_custom_target(sqlite-libs COMMAND openenclave::oeapkman add sqlite-dev
                                      sqlite-static)

add_executable(enclave enc.c stubs.c ${CMAKE_CURRENT_BINARY_DIR}/sqlite_t.c)

add_dependencies(enclave sqlite-libs)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file sqlite_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

get_target_property(APKMAN_ROOT openenclave::oeapkman ROOT)

# For sqlite headers.
target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          # sqlite include path.
          ${APKMAN_ROOT}/usr/include)

if (LVI_MITIGATION MATCHES ControlFlow)
  # Helper to enable compiler options for LVI mitigation.
  apply_lvi_mitigation(enclave)
  # Link against LVI-mitigated libraries.
  target_link_libraries(
    enclave openenclave::oeenclave-lvi-cfg -L${APKMAN_ROOT}/usr/lib
    libsqlite3.a openenclave::oecrypto${OE_CRYPTO_LIB}-lvi-cfg
    openenclave::oelibc-lvi-cfg)
else ()
  target_link_libraries(
    enclave openenclave::oeenclave "-L  ${APKMAN_ROOT}/usr/lib" libsqlite3.a
    openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibc)
endif ()
