# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# OS specific but arch agnostic files.
if (UNIX)
  set(PLATFORM_QUOTE_SRC
    ../common/cert.c
    crypto/openssl/asn1.c
    crypto/openssl/cert.c
    crypto/openssl/crl.c
    crypto/openssl/ec.c
    crypto/openssl/init.c
    crypto/openssl/key.c
    crypto/openssl/rsa.c
    linux/hostthread.c
    linux/time.c)

  set(PLATFORM_SRC
    ../common/asn1.c
    crypto/openssl/hmac.c
    crypto/openssl/random.c
    linux/windows.c
    ${PLATFORM_QUOTE_SRC})
elseif (WIN32)
  set(PLATFORM_SRC
    ../3rdparty/mbedtls/mbedtls/library/bignum.c
    crypto/bcrypt/hmac.c
    crypto/bcrypt/rsa.c
    windows/hostthread.c
    windows/time.c)
else()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

# SGX specific files
if (OE_SGX)
  set(NEW_QUOTE_SRC
    ../common/sgx/qeidentity.c
    ../common/sgx/quote.c
    ../common/sgx/report.c
    ../common/sgx/revocation.c
    ../common/sgx/sgxcertextensions.c
    ../common/sgx/tcbinfo.c
     sgx/quote_verify.c
     sgx/traceh.c)

  list(APPEND PLATFORM_QUOTE_SRC ${NEW_QUOTE_SRC})

  list(APPEND PLATFORM_SRC
    sgx/calls.c
    sgx/create.c
    sgx/elf.c
    sgx/enclave.c
    sgx/enclavemanager.c
    sgx/exception.c
    sgx/load.c
    sgx/loadelf.c
    sgx/loadpe.c
    sgx/ocalls.c
    sgx/quote.c
    sgx/registers.c
    sgx/report.c
    sgx/sgxload.c
    sgx/sgxmeasure.c
    sgx/sgxquote.c
    sgx/sgxsign.c
    sgx/sgxtypes.c
    sgx/traceh_enclave.c
    ${NEW_QUOTE_SRC})

  # OS specific as well.
  if (UNIX)
    set(NEW_QUOTE_SRC
      sgx/linux/sgxquoteprovider.c)

    list(APPEND PLATFORM_QUOTE_SRC ${NEW_QUOTE_SRC})

    list(APPEND PLATFORM_SRC
      sgx/linux/aep.S
      sgx/linux/aesm.c
      sgx/linux/enter.S
      sgx/linux/entersim.S
      sgx/linux/exception.c
      sgx/linux/sgxioctl.c
      ${NEW_QUOTE_SRC})
  else()
    list(APPEND PLATFORM_SRC
      sgx/windows/aep.asm
      sgx/windows/aesm.c
      sgx/windows/enter.asm
      sgx/windows/entersim.asm
      sgx/windows/exception.c)
  endif()

  set(PLATFORM_FLAGS "-m64")
elseif(OE_TRUSTZONE)
  list(APPEND PLATFORM_SRC
    optee/enclave.c
    optee/log.c)
  set(PLATFORM_FLAGS "")
endif()

set(NEW_QUOTE_SRC
  ../common/datetime.c
  ../common/safecrt.c
  hexdump.c
  result.c
  crypto/sha.c)

# Make quote verification library for Linux only
if (UNIX)
  add_library(oehostverify STATIC
    ${PLATFORM_QUOTE_SRC}
    ${NEW_QUOTE_SRC})
endif()

add_library(oehost STATIC
  ../common/datetime.c
  ../common/kdf.c
  ../common/safecrt.c
  dupenv.c
  error.c
  files.c
  fopen.c
  hexdump.c
  memalign.c
  ocalls.c
  result.c
  signkey.c
  strings.c
  tests.c
  crypto/sha.c
  ${PLATFORM_SRC}
  ${NEW_QUOTE_SRC})

# oehost and oehostverify share a lot of the same compiler/linker flags.
# Create an interface library that encapsulates all of them.
add_library(oehostinterface INTERFACE)
target_link_libraries(oehostinterface INTERFACE oe_includes)

# TODO: Replace these with `find_package` and add as dependencies to
# the CMake package.
if (UNIX)
  find_library(CRYPTO_LIB NAMES crypto)
  add_library(crypto SHARED IMPORTED)
  set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB})

  find_library(DL_LIB NAMES dl)
  add_library(dl SHARED IMPORTED)
  set_target_properties(dl PROPERTIES IMPORTED_LOCATION ${DL_LIB})
endif ()

find_package(Threads REQUIRED)

if (UNIX)
  target_link_libraries(oehostinterface INTERFACE crypto dl Threads::Threads)
elseif (WIN32)
  target_include_directories(oehostinterface INTERFACE
    ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  target_link_libraries(oehostinterface INTERFACE bcrypt Crypt32)
endif ()

# TODO: Handle Trust Zone etc.
if (USE_LIBSGX)
  find_library(LIBSGX_COMMON NAMES sgx_enclave_common)
  find_library(LIBSGX_QE NAMES sgx_dcap_ql)
  find_library(LIBSGX_URTS NAMES sgx_urts)

  if (NOT LIBSGX_COMMON OR NOT LIBSGX_QE OR NOT LIBSGX_URTS)
    message(FATAL_ERROR "No SGX libraries found, aborting! Set -DUSE_LIBSGX=OFF to ignore.")
  endif ()

  add_library(sgx_enclave_common SHARED IMPORTED)
  set_target_properties(sgx_enclave_common PROPERTIES IMPORTED_LOCATION ${LIBSGX_COMMON})

  add_library(sgx_dcap_ql SHARED IMPORTED)
  set_target_properties(sgx_dcap_ql PROPERTIES IMPORTED_LOCATION ${LIBSGX_QE})

  add_library(sgx_urts SHARED IMPORTED)
  set_target_properties(sgx_urts PROPERTIES IMPORTED_LOCATION ${LIBSGX_URTS})

  target_link_libraries(oehostinterface INTERFACE sgx_enclave_common sgx_dcap_ql sgx_urts)
  target_compile_definitions(oehostinterface INTERFACE OE_USE_LIBSGX)
endif ()

# Compile definitions and options
target_compile_definitions(oehostinterface
  INTERFACE
  # NOTE: This definition is public to the rest of our project's
  # targets, but should not yet be exposed to consumers of our
  # package.
  $<BUILD_INTERFACE:OE_API_VERSION=2>)

install(TARGETS oehostinterface EXPORT openenclave-targets)

# These are private to oehost, so we can't use the interface library.
set(OEHOST_PRIVATE_COMPILE_DEFS
  OE_BUILD_UNTRUSTED
  OE_REPO_BRANCH_NAME="${GIT_BRANCH}"
  OE_REPO_LAST_COMMIT="${GIT_COMMIT}")

set(OEHOST_PRIVATE_COMPILE_OPTIONS ${PLATFORM_FLAGS})

if (USE_DEBUG_MALLOC)
  list(APPEND OEHOST_PRIVATE_COMPILE_DEFS OE_USE_DEBUG_MALLOC)
endif()

if (UNIX)
  list(APPEND OEHOST_PRIVATE_COMPILE_DEFS _GNU_SOURCE)
  list(APPEND OEHOST_PRIVATE_COMPILE_OPTIONS -Wno-attributes -Wmissing-prototypes -fPIC)
endif()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  list(APPEND OEHOST_PRIVATE_COMPILE_OPTIONS -Wjump-misses-init)
endif ()

# Link the oehost and oehostverify with the oehostinterface library, so that
# they have the updated arguments. Also, add the private compile options.
target_link_libraries(oehost oehostinterface)
target_compile_definitions(oehost PRIVATE ${OEHOST_PRIVATE_COMPILE_DEFS})
target_compile_options(oehost PRIVATE ${OEHOST_PRIVATE_COMPILE_OPTIONS})

# TODO: Remove this hard coded output directory.
set_property(TARGET oehost PROPERTY
  ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# Install targets
install(TARGETS oehost EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

# Only create the host verification library in Linux systems.
if (UNIX)
  target_link_libraries(oehostverify oehostinterface)
  target_compile_definitions(oehostverify PRIVATE ${OEHOST_PRIVATE_COMPILE_DEFS})
  target_compile_options(oehostverify PRIVATE ${OEHOST_PRIVATE_COMPILE_OPTIONS})

  # TODO: Remove this hard coded output directory.
  set_property(TARGET oehostverify PROPERTY
    ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

  install(TARGETS oehostverify EXPORT openenclave-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host
    COMPONENT OEHOSTVERIFY)
endif()

# Create convenience libraries for apps that need the -rdynamic link flag.
add_library(oehostapp INTERFACE)
target_link_libraries(oehostapp INTERFACE oehost $<$<BOOL:UNIX>:-rdynamic>)
install(TARGETS oehostapp EXPORT openenclave-targets)

if (UNIX)
  add_library(oehostverifyapp INTERFACE)
  target_link_libraries(oehostverifyapp INTERFACE oehostverify $<$<BOOL:UNIX>:-rdynamic>)
  install(TARGETS oehostverifyapp EXPORT openenclave-targets)
endif()
