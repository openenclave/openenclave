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

add_executable(enclave enc.c main.c stubs.c
                       ${CMAKE_CURRENT_BINARY_DIR}/sqlite_t.c)

add_dependencies(enclave sqlite-libs)

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

# Need for the generated file sqlite_t.h
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Fetch the location of oeapkman binary.
get_target_property(OEAPKMAN openenclave::oeapkman LOCATION)

# Execute oeapkman once so that it is initialized.
execute_process(COMMAND "${OEAPKMAN}")

# Execute oeapkman again to fetch the root folder.
execute_process(COMMAND "${OEAPKMAN}" root
                OUTPUT_VARIABLE APKMAN_ROOT OUTPUT_STRIP_TRAILING_WHITESPACE)

# For sqlite headers.
target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
          # sqlite include path.
          ${APKMAN_ROOT}/usr/include)

target_link_libraries(
  enclave openenclave::oeenclave "-L  ${APKMAN_ROOT}/usr/lib" libsqlite3.a
  openenclave::oecrypto${OE_CRYPTO_LIB} openenclave::oelibc)
