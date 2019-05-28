# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

##==============================================================================
##
## These rules generate the edge routines for the POSIX interface, which is
## installed by oe_register_posix_ecall_function_table().
##
##==============================================================================

set(EDL_DIR ${CMAKE_SOURCE_DIR}/common)
set(EDL_FILE ${EDL_DIR}/posix.edl)

add_custom_command(
    OUTPUT posix_u.h posix_u.c posix_args.h
    DEPENDS ${EDL_FILE}
    COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${EDL_FILE})

add_custom_target(posix_untrusted_edl
    DEPENDS posix_u.h posix_u.c posix_args.h)

##==============================================================================
##
## these rules build the oehost target.
##
##==============================================================================

# OS specific but arch agnostic files.
if (UNIX)
  set(PLATFORM_SRC
    ../common/asn1.c
    ../common/cert.c
    crypto/openssl/asn1.c
    crypto/openssl/cert.c
    crypto/openssl/crl.c
    crypto/openssl/ec.c
    crypto/openssl/hmac.c
    crypto/openssl/init.c
    crypto/openssl/key.c
    crypto/openssl/random.c
    crypto/openssl/rsa.c
    linux/hostthread.c
    linux/posix.c
    linux/time.c
    linux/windows.c)
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
  list(APPEND PLATFORM_SRC
    ../common/sgx/qeidentity.c
    ../common/sgx/quote.c
    ../common/sgx/report.c
    ../common/sgx/revocation.c
    ../common/sgx/sgxcertextensions.c
    ../common/sgx/tcbinfo.c
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
    sgx/traceh.c)

  # OS specific as well.
  if (UNIX)
    list(APPEND PLATFORM_SRC
      sgx/linux/aep.S
      sgx/linux/aesm.c
      sgx/linux/enter.S
      sgx/linux/entersim.S
      sgx/linux/exception.c
      sgx/linux/sgxioctl.c
      sgx/linux/sgxquoteprovider.c
      sgx/linux/xstate.c)
  else()
    list(APPEND PLATFORM_SRC
      sgx/windows/aep.asm
      sgx/windows/aesm.c
      sgx/windows/enter.asm
      sgx/windows/entersim.asm
      sgx/windows/exception.c
      sgx/windows/xstate.c)
  endif()

  set(PLATFORM_FLAGS "-m64")
elseif(OE_TRUSTZONE)
  list(APPEND PLATFORM_SRC
    optee/enclave.c
    optee/log.c)
  set(PLATFORM_FLAGS "")
endif()

# Combine with all other non platform dependent files.
add_library(oehost STATIC
  ../common/datetime.c
  ../common/kdf.c
  ../common/safecrt.c
  asym_keys.c
  dupenv.c
  error.c
  files.c
  fopen.c
  hexdump.c
  posix_u_wrapper.c
  memalign.c
  ocalls.c
  result.c
  signkey.c
  strings.c
  tests.c
  crypto/sha.c
  ${PLATFORM_SRC})

target_link_libraries(oehost PUBLIC oe_includes)

add_dependencies(oehost posix_untrusted_edl)

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
  target_link_libraries(oehost PRIVATE crypto dl Threads::Threads)
elseif (WIN32)
  target_include_directories(oehost PRIVATE
    ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  target_link_libraries(oehost PRIVATE bcrypt Crypt32)
endif ()

# For including edge routines.
target_include_directories(oehost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

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

  target_link_libraries(oehost PUBLIC sgx_enclave_common sgx_dcap_ql sgx_urts)
  target_compile_definitions(oehost PUBLIC OE_USE_LIBSGX)
endif ()

# Compile definitions and options
target_compile_definitions(oehost
  PUBLIC
  # NOTE: This definition is public to the rest of our project's
  # targets, but should not yet be exposed to consumers of our
  # package.
  $<BUILD_INTERFACE:OE_API_VERSION=2>
  PRIVATE
  OE_BUILD_UNTRUSTED
  OE_REPO_BRANCH_NAME="${GIT_BRANCH}"
  OE_REPO_LAST_COMMIT="${GIT_COMMIT}")

if (USE_DEBUG_MALLOC)
  target_compile_definitions(oehost PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

if (UNIX)
  target_compile_options(oehost
     PRIVATE -Wno-attributes -Wmissing-prototypes -fPIC ${PLATFORM_FLAGS}
     PUBLIC -fstack-protector-strong)
  target_compile_definitions(oehost
     PRIVATE _GNU_SOURCE
     PUBLIC $<$<NOT:$<CONFIG:debug>>:_FORTIFY_SOURCE=2>)
endif ()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  target_compile_options(oehost PRIVATE -Wjump-misses-init)
endif ()

# TODO: Remove this hard coded output directory.
set_property(TARGET oehost PROPERTY
  ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# Convenience library for creating a host-app (that needs the
# -rdynamic link flag).
add_library(oehostapp INTERFACE)

target_link_libraries(oehostapp INTERFACE oehost)

if (UNIX)
  target_link_libraries(oehostapp INTERFACE
      -rdynamic
      -Wl,-z,noexecstack)
endif ()

# Install targets
install(TARGETS oehost EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

install(TARGETS oehostapp EXPORT openenclave-targets)
