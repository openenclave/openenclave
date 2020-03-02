# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

##==============================================================================
##
## These rules generate the edge routines for the internal TEE-agnostic
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

set(EDL_DIR ${CMAKE_SOURCE_DIR}/common)

set(TEE_EDL_FILE ${EDL_DIR}/tee.edl)

add_custom_command(
    OUTPUT tee_u.h tee_u.c tee_args.h
    DEPENDS ${TEE_EDL_FILE} edger8r
    COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${TEE_EDL_FILE})

add_custom_target(tee_untrusted_edl
    DEPENDS tee_u.h tee_u.c tee_args.h)

##==============================================================================
##
## These rules generate the edge routines for the internal ECALLs/OCALLs used
## by switchless calls.
##
##==============================================================================
if (OE_SGX)
    set(SWITCHLESS_EDL_FILE ${EDL_DIR}/sgx/switchless.edl)

    add_custom_command(
        OUTPUT switchless_u.h switchless_u.c switchless_args.h
        DEPENDS ${SWITCHLESS_EDL_FILE} edger8r
        COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${SWITCHLESS_EDL_FILE})

    add_custom_target(switchless_untrusted_edl
        DEPENDS switchless_u.h switchless_u.c switchless_args.h)
endif()

##==============================================================================
##
## These rules generate the edge routines for the internal SGX-specific
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

if(OE_SGX)
    set(SGX_EDL_FILE ${EDL_DIR}/sgx/sgx.edl)

    add_custom_command(
        OUTPUT sgx_u.h sgx_u.c sgx_args.h
        DEPENDS ${SGX_EDL_FILE} edger8r
        COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${SGX_EDL_FILE})

    add_custom_target(sgx_untrusted_edl
        DEPENDS sgx_u.h sgx_u.c sgx_args.h)
endif()

##==============================================================================
##
## These rules generate the edge routines for the SYSCALL interface, which is
## installed by oe_register_syscall_ecall_function_table().
##
##==============================================================================

set(SYSCALL_EDL ${EDL_DIR}/syscall.edl)

add_custom_command(
    OUTPUT syscall_u.h syscall_u.c syscall_args.h
    DEPENDS ${SYSCALL_EDL} edger8r
    COMMAND edger8r --search-path ${EDL_DIR} --untrusted ${SYSCALL_EDL})

add_custom_target(syscall_untrusted_edl
    DEPENDS syscall_u.h syscall_u.c syscall_args.h)

##==============================================================================
##
## these rules build the oehost target.
##
##==============================================================================

# OS specific but arch agnostic files.
if (UNIX)
  set(PLATFORM_HOST_ONLY_SRC
    ../common/cert.c
    crypto/openssl/asn1.c
    crypto/openssl/cert.c
    crypto/openssl/crl.c
    crypto/openssl/ec.c
    crypto/openssl/init.c
    crypto/openssl/key.c
    crypto/openssl/rsa.c
    crypto/openssl/sha.c
    linux/hostthread.c)

  set(PLATFORM_SDK_ONLY_SRC
    ../common/asn1.c
    crypto/openssl/hmac.c
    crypto/openssl/random.c
    linux/syscall.c
    linux/time.c
    linux/windows.c)
elseif (WIN32)
  set(PLATFORM_HOST_ONLY_SRC
    ../common/cert.c
    crypto/bcrypt/cert.c
    crypto/bcrypt/crl.c
    crypto/bcrypt/ec.c
    crypto/bcrypt/key.c
    crypto/bcrypt/rsa.c
    crypto/bcrypt/sha.c
    crypto/bcrypt/pem.c
    crypto/bcrypt/util.c
    windows/hostthread.c)

  set(PLATFORM_SDK_ONLY_SRC
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
else()
  message(FATAL_ERROR "Unknown OS. Only supported OSes are Linux and Windows")
endif()

if (OE_SGX AND WIN32)
  # Use clang to compile the oe_enter function that calls ENCLU.
  # Windows debuggers (WinDbg and Visual Studio Debugger) require that the rbp
  # is set up like a Linux x64 ABI style frame pointer by the oe_enter function.
  # Since oe_enter function is setting up the frame-pointer, enter.c must be
  # compiled with the -fomit-frame-pointer flag so that the compiler does not
  # set up the frame pointer.
  add_custom_command(
     OUTPUT enter.obj
     DEPENDS sgx/enter.c
     COMMAND clang  -c -O2 -fomit-frame-pointer -m64
             -I${PROJECT_SOURCE_DIR}/include
             ${CMAKE_CURRENT_SOURCE_DIR}/sgx/enter.c
             -o enter.obj)
endif()

# SGX specific files.
if (OE_SGX)
  list(APPEND PLATFORM_HOST_ONLY_SRC
    ../common/sgx/endorsements.c
    ../common/sgx/qeidentity.c
    ../common/sgx/quote.c
    ../common/sgx/report.c
    ../common/sgx/revocation.c
    ../common/sgx/sgxcertextensions.c
    ../common/sgx/tcbinfo.c
    ../common/sgx/tlsverifier.c
    ../common/sgx/verifier.c
    sgx/hostverify_report.c
    sgx/sgxquoteprovider.c)

  list(APPEND PLATFORM_SDK_ONLY_SRC
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
    sgx/sgx_u_wrapper.c
    sgx/sgxload.c
    sgx/sgxmeasure.c
    sgx/sgxquote.c
    sgx/sgxsign.c
    sgx/sgxtypes.c
    sgx/switchless.c
    sgx/switchless_u_wrapper.c)


  # OS specific as well.
  if (UNIX)
    list(APPEND PLATFORM_HOST_ONLY_SRC
        sgx/linux/sgxquoteproviderloader.c)

    list(APPEND PLATFORM_SDK_ONLY_SRC
      sgx/linux/aep.S
      sgx/enter.c
      sgx/linux/exception.c
      sgx/linux/sgxioctl.c
      sgx/linux/switchless.c
      sgx/linux/xstate.c)
  else()
    list(APPEND PLATFORM_HOST_ONLY_SRC
      sgx/windows/sgxquoteproviderloader.c)

    list(APPEND PLATFORM_SDK_ONLY_SRC
      sgx/windows/aep.asm
      ${CMAKE_CURRENT_BINARY_DIR}/enter.obj
      sgx/windows/exception.c
      sgx/windows/switchless.c
      sgx/windows/xstate.c)
  endif()

  set(PLATFORM_FLAGS "-m64")
elseif(OE_TRUSTZONE)
  list(APPEND PLATFORM_SDK_ONLY_SRC
    optee/log.c)

  if (UNIX)
    list(APPEND PLATFORM_SDK_ONLY_SRC
      optee/linux/enclave.c)
  else()
    message(FATAL_ERROR "OP-TEE is not yet supported on platforms other than Linux.")
  endif()

  set(PLATFORM_FLAGS "")
endif()

if (OE_SGX AND WIN32)
  # oedebugrt is accessed via a bridge on Win32 and need not be linked.
  list(APPEND PLATFORM_SDK_ONLY_SRC
    sgx/windows/debugrtbridge.c)

  # __oe_dispatch_ocall function must have debug symbols for debuggers to
  # stitch the ocall stack. Use /Z7 flag to embed the debugging information
  # in the object file. When a host application is built, the linker will
  # extract this debugging information and put it in the pdb for the host
  # application. Using /Z7 avoids having to distribut oehost.pdb.
  # Note: This is a temporary fix and debuggers will not have this requirement
  # when ocall stack stitching is also done via the debugger contract.
  set_source_files_properties(
    sgx/calls.c
    PROPERTIES COMPILE_FLAGS "/Z7")
endif()

# Common host verification files that work on any OS/architecture.
list(APPEND PLATFORM_HOST_ONLY_SRC
  ../common/attest_plugin.c
  ../common/datetime.c
  ../common/safecrt.c
  hexdump.c
  dupenv.c
  fopen.c
  tests.c
  result.c
  traceh.c)

# Common files that are used in the OE SDK only.
list(APPEND PLATFORM_SDK_ONLY_SRC
  ../common/kdf.c
  ../common/argv.c
  asym_keys.c
  calls.c
  ocalls.c
  error.c
  files.c
  fopen.c
  memalign.c
  syscall_u_wrapper.c
  signkey.c
  strings.c
  tee_u_wrapper.c
  traceh_enclave.c)

# Combine the following common code along with the platform specific code and
# host verification code to get the full oehost target provided by the OE SDK.
add_library(oehost STATIC
  ${PLATFORM_HOST_ONLY_SRC}
  ${PLATFORM_SDK_ONLY_SRC})

add_library(oehostverify STATIC ${PLATFORM_HOST_ONLY_SRC})

target_link_libraries(oehostverify PUBLIC oe_includes)
target_link_libraries(oehost PUBLIC oe_includes)

if(WIN32)
  target_link_libraries(oehost PUBLIC ws2_32)
endif()

if (OE_SGX AND UNIX)
  # Link oedebugrt static library.
  target_link_libraries(oehost PRIVATE oedebugrt)

  # enter.c must be forced to retain the frame-pointer
  # for ocall stack-stitching by using the -fno-omit-frame-pointer flag.
  # It is compiled with -O2 flag to retain the same generated assembly
  # code in both debug and release builds.
  set_source_files_properties(oehost
    sgx/enter.c
    PROPERTIES
    COMPILE_FLAGS "-O2 -fno-omit-frame-pointer")
endif()

add_dependencies(oehost syscall_untrusted_edl)
add_dependencies(oehost tee_untrusted_edl)
if(OE_SGX)
  add_dependencies(oehost sgx_untrusted_edl switchless_untrusted_edl)
endif()

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
      set_target_properties(openenclave::crypto PROPERTIES IMPORTED_LOCATION ${CRYPTO_LIB})
    endif ()
  endif ()

  if (NOT TARGET openenclave::dl)
    find_library(DL_LIB NAMES dl)
    if (NOT DL_LIB)
      message(FATAL_ERROR "-- Looking for dl library - not found")
    else ()
      message("-- Looking for dl library - found")
      add_library(openenclave::dl SHARED IMPORTED)
      set_target_properties(openenclave::dl PROPERTIES IMPORTED_LOCATION ${DL_LIB})
    endif ()
  endif ()
endif ()

find_package(Threads REQUIRED)

if (UNIX)
  target_link_libraries(oehost PRIVATE
      openenclave::crypto
      openenclave::dl
      Threads::Threads)
  target_link_libraries(oehostverify PRIVATE
      openenclave::crypto
      openenclave::dl
      Threads::Threads)

  if (OE_TRUSTZONE)
    target_include_directories(oehost PRIVATE
      ${OE_TZ_OPTEE_CLIENT_INC})
    target_link_libraries(oehost PRIVATE teec)
  endif ()
elseif (WIN32)
  target_include_directories(oehost PRIVATE
    ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  # Synchronization library is needed for WaitOnAddress/WakeByAddress functions
  # used by switchless ocalls worker threads.
  target_link_libraries(oehost PRIVATE bcrypt Crypt32 Synchronization)
  target_include_directories(oehostverify PRIVATE
    ${CMAKE_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  target_link_libraries(oehostverify PRIVATE bcrypt Crypt32)

  # TODO: Handle TrustZone on Windows.
endif ()

# For including edge routines.
target_include_directories(oehost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (OE_SGX)
  # Always link with the EnclaveCommonAPI
  if (WIN32)
    set(LIBPATHS ${NUGET_PACKAGE_PATH}/EnclaveCommonAPI/lib/native/x64-Release)
    set(INCPATHS "${NUGET_PACKAGE_PATH}/EnclaveCommonAPI/Header Files")
  endif ()
  if (NOT LIBPATHS)
    set(LIBPATHS "/usr")
  endif ()
  find_library(LIBSGX_COMMON NAMES sgx_enclave_common HINTS ${LIBPATHS})
  if (NOT LIBSGX_COMMON)
    message(FATAL_ERROR "Intel SGX EnclaveCommonAPI library not found, aborting!")
  endif ()
  add_library(sgx_enclave_common SHARED IMPORTED)
  if (WIN32)
     set_target_properties(sgx_enclave_common PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${INCPATHS}"
        IMPORTED_LOCATION $ENV{WINDIR}/System32
        IMPORTED_IMPLIB ${LIBSGX_COMMON})
  elseif (UNIX)
    set_target_properties(sgx_enclave_common PROPERTIES IMPORTED_LOCATION ${LIBSGX_COMMON})
  endif ()
  target_link_libraries(oehost PUBLIC $<BUILD_INTERFACE:sgx_enclave_common>)

  # Optionally link in DCAP library
  if (HAS_QUOTE_PROVIDER)
    if (WIN32)
      list(APPEND LIBPATHS
          ${NUGET_PACKAGE_PATH}/DCAP_Components/build/lib/native/Libraries)
      list(APPEND INCPATHS
          "${NUGET_PACKAGE_PATH}/DCAP_Components/build/Header Files")
    endif ()
    find_library(LIBSGX_QE NAMES sgx_dcap_ql HINTS ${LIBPATHS})
    if (NOT LIBSGX_QE)
      message(FATAL_ERROR "No quote provider library found, aborting! Set -DHAS_QUOTE_PROVIDER=OFF to ignore.")
    endif ()
    add_library(sgx_dcap_ql SHARED IMPORTED)
    if (WIN32)
      set_target_properties(sgx_dcap_ql PROPERTIES
          INTERFACE_INCLUDE_DIRECTORIES "${INCPATHS}"
          IMPORTED_LOCATION $ENV{WINDIR}/System32
          IMPORTED_IMPLIB ${LIBSGX_QE})
    elseif (UNIX)
      set_target_properties(sgx_dcap_ql PROPERTIES IMPORTED_LOCATION ${LIBSGX_QE})
    endif ()
    target_link_libraries(oehost PUBLIC $<BUILD_INTERFACE:sgx_dcap_ql>)
    # turn on 'OE_LINK_SGX_DCAP_QL' for the preprocessor
    target_compile_definitions(oehost PUBLIC OE_LINK_SGX_DCAP_QL)
  endif ()
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

# Use the same the compile options and definitions from oehost.
target_compile_options(oehostverify
  PRIVATE $<TARGET_PROPERTY:oehost,COMPILE_OPTIONS>
  INTERFACE $<TARGET_PROPERTY:oehost,INTERFACE_COMPILE_OPTIONS>)

target_compile_definitions(oehostverify
  PRIVATE $<TARGET_PROPERTY:oehost,COMPILE_DEFINITIONS>
  INTERFACE $<TARGET_PROPERTY:oehost,INTERFACE_COMPILE_DEFINITIONS>)


# TODO: Remove this hard coded output directory.
set_property(TARGET oehost PROPERTY
  ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/host)

# Convenience library for creating a host-app (that needs the
# -rdynamic link flag). We do this by default for the oehostverify target too.
add_library(oehostapp INTERFACE)

target_link_libraries(oehostapp INTERFACE oehost)

if (UNIX)
  target_link_libraries(oehost INTERFACE
      -Wl,-z,noexecstack)
  target_link_libraries(oehostapp INTERFACE
      -rdynamic)
  target_link_libraries(oehostverify INTERFACE
      -Wl,-z,noexecstack
      -rdynamic)
endif ()

# Install targets
install(TARGETS oehost EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host)

install(TARGETS oehostapp EXPORT openenclave-targets)

install(TARGETS oehostverify EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host
  COMPONENT OEHOSTVERIFY)
