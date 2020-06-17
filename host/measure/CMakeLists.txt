# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# Add a library oehostmr independent of libsgx_enclave_common/libsgx_dcap_ql
if (UNIX)
  set(PLATFORM_HOST_MR_SRC
      crypto/openssl/asn1.c
      crypto/openssl/cert.c
      crypto/openssl/ec.c
      crypto/openssl/init.c
      crypto/openssl/key.c
      crypto/openssl/rsa.c
      crypto/openssl/sha.c
      linux/hostthread.c)
elseif (WIN32)
  set(PLATFORM_HOST_MR_SRC
      crypto/bcrypt/key.c
      crypto/bcrypt/rsa.c
      crypto/bcrypt/sha.c
      crypto/bcrypt/pem.c
      crypto/bcrypt/util.c
      windows/hostthread.c
      ../3rdparty/mbedtls/mbedtls/library/bignum.c
      ../3rdparty/mbedtls/mbedtls/library/platform_util.c #Used by bignum.c
      ../common/asn1.c
      ../common/cert.c
      crypto/bcrypt/cert.c
      crypto/bcrypt/crl.c
      crypto/bcrypt/ec.c
      crypto/bcrypt/hmac.c
      crypto/bcrypt/key.c
      crypto/bcrypt/pem.c
      crypto/bcrypt/random.c
      crypto/bcrypt/rsa.c
      crypto/bcrypt/sha.c
      windows/hostthread.c
      windows/syscall.c
      windows/time.c)
else ()
  message(
    FATAL_ERROR "Unknown OS. The only supported OSes are Linux and Windows")
endif ()

if (OE_SGX)
  list(
    APPEND
    PLATFORM_HOST_MR_SRC
    signkey.c
    ../common/sgx/sgxmeasure.c
    sgx/create.c
    sgx/elf.c
    sgx/load.c
    sgx/loadelf.c
    sgx/sgxload.c
    sgx/sgxsign.c
    sgx/sgxtypes.c
    ../common/sgx/report_helper.c)

  if (WITH_EEID)
    list(APPEND PLATFORM_HOST_MR_SRC ../common/sgx/eeid.c)
  endif ()

  # OS specific as well.
  if (UNIX)
    list(APPEND PLATFORM_HOST_MR_SRC sgx/linux/xstate.c)
  else ()
    list(APPEND PLATFORM_HOST_MR_SRC sgx/windows/xstate.c)
  endif ()

  set(PLATFORM_FLAGS "-m64")
elseif (OE_TRUSTZONE)
  list(APPEND PLATFORM_HOST_MR_SRC optee/log.c)

  if (UNIX)
    list(APPEND PLATFORM_HOST_MR_SRC optee/linux/enclave.c)
  else ()
    message(
      FATAL_ERROR "OP-TEE is not yet supported on platforms other than Linux.")
  endif ()

  set(PLATFORM_FLAGS "")
endif ()

# Common host verification files that work on any OS/architecture.
list(
  APPEND
  PLATFORM_HOST_MR_SRC
  ../common/safecrt.c
  ../common/sha.c
  hexdump.c
  dupenv.c
  fopen.c
  result.c
  traceh.c)

# Common files that are used in the OE SDK only.
list(APPEND PLATFORM_HOST_MR_SRC memalign.c strings.c)

add_library(oehostmr STATIC ${PLATFORM_HOST_MR_SRC})

target_link_libraries(oehostmr PUBLIC oe_includes)

if (WIN32)
  target_link_libraries(oehostmr PUBLIC ws2_32)
  target_link_libraries(oehostmr PUBLIC Bcrypt)
  target_link_libraries(oehostmr PUBLIC crypt32)
endif ()

add_dependencies(oehostmr syscall_untrusted_edl core_untrusted_edl)
if (OE_SGX)
  add_dependencies(oehostmr platform_untrusted_edl)
endif ()

# TODO: Replace these with `find_package` and add as dependencies to
# the CMake package.
if (UNIX)
  if (NOT TARGET openenclave::crypto)
    find_library(CRYPTO_LIB NAMES crypto)
    if (NOT CRYPTO_LIB)
      message(FATAL_ERROR "-- Looking for crypto library - not found")
    else ()
      message("-- Looking for crypto library - found")
      add_library(openenclave::crypto SHARED IMPORTED)
      set_target_properties(openenclave::crypto PROPERTIES IMPORTED_LOCATION
                                                           ${CRYPTO_LIB})
    endif ()
  endif ()

  if (NOT TARGET openenclave::dl)
    find_library(DL_LIB NAMES dl)
    if (NOT DL_LIB)
      message(FATAL_ERROR "-- Looking for dl library - not found")
    else ()
      message("-- Looking for dl library - found")
      add_library(openenclave::dl SHARED IMPORTED)
      set_target_properties(openenclave::dl PROPERTIES IMPORTED_LOCATION
                                                       ${DL_LIB})
    endif ()
  endif ()
endif ()

find_package(Threads REQUIRED)

if (UNIX)
  target_link_libraries(oehostmr PRIVATE openenclave::crypto Threads::Threads)
  if (OE_TRUSTZONE)
    target_include_directories(oehostmr PRIVATE ${OE_TZ_OPTEE_CLIENT_INC})
    target_link_libraries(oehostmr PRIVATE teec)
  endif ()
elseif (WIN32)
  target_include_directories(
    oehostmr PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
endif ()

# For including edge routines.
target_include_directories(oehostmr PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

# Compile definitions and options
target_compile_definitions(
  oehostmr
  PUBLIC # NOTE: This definition is public to the rest of our project's
         # targets, but should not yet be exposed to consumers of our
         # package.
         $<BUILD_INTERFACE:OE_API_VERSION=2>
  PRIVATE OE_BUILD_UNTRUSTED OE_REPO_BRANCH_NAME="${GIT_BRANCH}"
          OE_REPO_LAST_COMMIT="${GIT_COMMIT}")

if (USE_DEBUG_MALLOC)
  target_compile_definitions(oehostmr PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

if (WITH_EEID)
  target_compile_definitions(oehostmr PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()

if (UNIX)
  target_compile_options(
    oehostmr
    PRIVATE -Wno-attributes -Wmissing-prototypes -fPIC ${PLATFORM_FLAGS}
    PUBLIC -fstack-protector-strong)
  target_compile_definitions(
    oehostmr
    PRIVATE _GNU_SOURCE
    PUBLIC $<$<NOT:$<CONFIG:debug>>:_FORTIFY_SOURCE=2>)
endif ()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  target_compile_options(oehostmr PRIVATE -Wjump-misses-init)
endif ()

target_compile_options(oehostmr PRIVATE -DOEHOSTMR)
set_property(TARGET oehostmr PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                                      ${OE_LIBDIR}/openenclave/host)

if (UNIX)
  target_link_libraries(oehostmr INTERFACE -Wl,-z,noexecstack)
endif ()
