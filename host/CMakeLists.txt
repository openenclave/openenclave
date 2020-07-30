# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

set(OE_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(EDL_DIR ${PROJECT_SOURCE_DIR}/include/openenclave/edl)

##==============================================================================
##
## These rules generate the edge routines for the internal TEE-agnostic
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

set(CORE_EDL_FILE ${EDL_DIR}/core.edl)
if (COMPILE_SYSTEM_EDL)
  add_custom_command(
    OUTPUT core_u.h core_u.c core_args.h
    DEPENDS ${CORE_EDL_FILE} edger8r
    COMMAND edger8r --search-path ${OE_INCLUDE_DIR} --untrusted
            ${CORE_EDL_FILE})

  add_custom_target(core_untrusted_edl DEPENDS core_u.h core_u.c core_args.h)

  list(APPEND PLATFORM_SDK_ONLY_SRC core_u_wrapper.c)
else ()
  # Only generate headers
  add_custom_command(
    OUTPUT core_u.h core_args.h
    DEPENDS ${CORE_EDL_FILE} edger8r
    COMMAND edger8r --header-only --search-path ${OE_INCLUDE_DIR} --untrusted
            ${CORE_EDL_FILE})

  add_custom_target(core_untrusted_edl DEPENDS core_u.h core_args.h)
endif ()

##==============================================================================
##
## Generate header (*_args.h) that defines data structures from EDL files.
## Note that doing this on the host side to ensure publishing the header with
## the case of `BUILD_ENCLAVES=OFF`.
##
##==============================================================================

set(OE_EDL_INCLUDE_DIR ${OE_INCDIR}/openenclave/bits)
set(OE_PRIV_EDL_INCLUDE_DIR ${OE_INCDIR}/openenclave/internal/bits)
set(OE_PRIV_SGX_EDL_INCLUDE_DIR ${OE_INCDIR}/openenclave/internal/bits/sgx)

list(APPEND EDL_PUBLIC_STRUCTURES "${EDL_DIR}/asym_keys.edl"
     "${EDL_DIR}/time.edl")
list(APPEND EDL_PRIVATE_STRUCTURES "${EDL_DIR}/fcntl.edl" "${EDL_DIR}/poll.edl"
     "${EDL_DIR}/socket.edl" "${EDL_DIR}/utsname.edl")
list(APPEND EDL_PRIVATE_SGX_STRUCTURES "${EDL_DIR}/sgx/switchless.edl")

function (edl_to_header EDL_FILE OUT_DIR)
  get_filename_component(name ${EDL_FILE} NAME_WE)

  add_custom_command(
    OUTPUT ${name}_args.h
    DEPENDS ${EDL_FILE} edger8r
    COMMAND edger8r --header-only --untrusted ${EDL_FILE})

  add_custom_command(
    OUTPUT ${OUT_DIR}/${name}.h
    COMMAND ${CMAKE_COMMAND} -E copy ${name}_args.h ${OUT_DIR}/${name}.h
    DEPENDS ${name}_args.h)

  add_custom_target(gen_edl_headers_${name} DEPENDS ${OUT_DIR}/${name}.h)

  # Add dependencies to `oe_includes` so that the published header will be ready before
  # other files consume it.
  add_dependencies(oe_includes gen_edl_headers_${name})
endfunction ()

foreach (struct_file ${EDL_PUBLIC_STRUCTURES})
  edl_to_header(${struct_file} ${OE_EDL_INCLUDE_DIR})
endforeach ()

foreach (struct_file ${EDL_PRIVATE_STRUCTURES})
  edl_to_header(${struct_file} ${OE_PRIV_EDL_INCLUDE_DIR})
endforeach ()

foreach (struct_file ${EDL_PRIVATE_SGX_STRUCTURES})
  edl_to_header(${struct_file} ${OE_PRIV_SGX_EDL_INCLUDE_DIR})
endforeach ()

# Only install the public EDL headers
install(DIRECTORY ${OE_EDL_INCLUDE_DIR}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/openenclave)

##==============================================================================
##
## These rules generate the edge routines for the internal SGX-specific
## ECALLs/OCALLs used by liboehost/liboecore.
##
##==============================================================================

set(SGX_EDL_FILE ${EDL_DIR}/sgx/platform.edl)
if (OE_SGX AND COMPILE_SYSTEM_EDL)
  add_custom_command(
    OUTPUT platform_u.h platform_u.c platform_args.h
    DEPENDS ${SGX_EDL_FILE} edger8r
    COMMAND edger8r --search-path ${OE_INCLUDE_DIR} --untrusted ${SGX_EDL_FILE})

  add_custom_target(platform_untrusted_edl DEPENDS platform_u.h platform_u.c
                                                   platform_args.h)

  list(APPEND PLATFORM_SDK_ONLY_SRC sgx/platform_u_wrapper.c)
elseif (OE_SGX)
  add_custom_command(
    OUTPUT platform_u.h platform_args.h
    DEPENDS ${SGX_EDL_FILE} edger8r
    COMMAND edger8r --header-only --search-path ${OE_INCLUDE_DIR} --untrusted
            ${SGX_EDL_FILE})

  add_custom_target(platform_untrusted_edl DEPENDS platform_u.h platform_args.h)
endif ()

##==============================================================================
##
## These rules generate the edge routines for the SYSCALL interface, which is
## installed by oe_register_syscall_ecall_function_table().
##
##==============================================================================

set(SYSCALL_EDL ${EDL_DIR}/syscall.edl)
if (COMPILE_SYSTEM_EDL)
  add_custom_command(
    OUTPUT syscall_u.h syscall_u.c syscall_args.h
    DEPENDS ${SYSCALL_EDL} edger8r
    COMMAND edger8r --search-path ${OE_INCLUDE_DIR} --untrusted ${SYSCALL_EDL})

  add_custom_target(syscall_untrusted_edl DEPENDS syscall_u.h syscall_u.c
                                                  syscall_args.h)

  list(APPEND PLATFORM_SDK_ONLY_SRC syscall_u_wrapper.c)
else ()
  add_custom_command(
    OUTPUT syscall_u.h syscall_args.h
    DEPENDS ${SYSCALL_EDL} edger8r
    COMMAND edger8r --header-only --search-path ${OE_INCLUDE_DIR} --untrusted
            ${SYSCALL_EDL})

  add_custom_target(syscall_untrusted_edl DEPENDS syscall_u.h syscall_args.h)
endif ()

##==============================================================================
##
## these rules build the oehost target.
##
##==============================================================================

# OS specific but arch agnostic files.
if (UNIX)
  list(
    APPEND
    PLATFORM_HOST_ONLY_SRC
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

  list(
    APPEND
    PLATFORM_SDK_ONLY_SRC
    ../common/asn1.c
    crypto/openssl/hmac.c
    crypto/openssl/random.c
    linux/syscall.c
    linux/time.c)
elseif (WIN32)
  list(
    APPEND
    PLATFORM_HOST_ONLY_SRC
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

  list(
    APPEND
    PLATFORM_SDK_ONLY_SRC
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
    COMMAND
      clang -c -O2 -fomit-frame-pointer -m64 -I${PROJECT_SOURCE_DIR}/include
      -I${OE_INCDIR} ${CMAKE_CURRENT_SOURCE_DIR}/sgx/enter.c -o enter.obj)
endif ()

# SGX specific files.
if (OE_SGX)
  list(
    APPEND
    PLATFORM_HOST_ONLY_SRC
    ../common/sgx/endorsements.c
    ../common/sgx/qeidentity.c
    ../common/sgx/quote.c
    ../common/sgx/report.c
    ../common/sgx/report_helper.c
    ../common/sgx/collateral.c
    ../common/sgx/sgxcertextensions.c
    ../common/sgx/sgxmeasure.c
    ../common/sgx/tcbinfo.c
    ../common/sgx/tlsverifier.c
    ../common/sgx/verifier.c
    sgx/hostverify_report.c
    sgx/sgxquoteprovider.c)

  if (WITH_EEID)
    list(APPEND PLATFORM_HOST_ONLY_SRC ../common/sgx/eeid_verifier.c
         ../common/sgx/eeid.c)
  endif ()

  list(
    APPEND
    PLATFORM_SDK_ONLY_SRC
    sgx/calls.c
    sgx/create.c
    sgx/elf.c
    sgx/enclave.c
    sgx/enclavemanager.c
    sgx/exception.c
    sgx/load.c
    sgx/loadelf.c
    sgx/ocalls.c
    sgx/quote.c
    sgx/registers.c
    sgx/report.c
    sgx/sgx_enclave_common_wrapper.c
    sgx/sgxload.c
    sgx/sgxquote.c
    sgx/sgxsign.c
    sgx/sgxtypes.c
    sgx/switchless.c
    sgx/tests.c)

  # OS specific as well.
  if (UNIX)
    list(APPEND PLATFORM_HOST_ONLY_SRC sgx/linux/sgxquoteproviderloader.c)

    list(
      APPEND
      PLATFORM_SDK_ONLY_SRC
      sgx/linux/aep.S
      sgx/enter.c
      sgx/linux/exception.c
      sgx/linux/sgxioctl.c
      sgx/linux/switchless.c
      sgx/linux/sgxquoteexloader.c
      sgx/linux/xstate.c)
  else ()
    list(APPEND PLATFORM_HOST_ONLY_SRC sgx/windows/sgxquoteproviderloader.c)

    list(
      APPEND
      PLATFORM_SDK_ONLY_SRC
      sgx/windows/aep.asm
      ${CMAKE_CURRENT_BINARY_DIR}/enter.obj
      sgx/windows/exception.c
      sgx/windows/switchless.c
      sgx/windows/sgxquoteexloader.c
      sgx/windows/xstate.c)
  endif ()

  set(PLATFORM_FLAGS "-m64")
elseif (OE_TRUSTZONE)
  list(APPEND PLATFORM_SDK_ONLY_SRC optee/log.c)

  if (UNIX)
    list(APPEND PLATFORM_SDK_ONLY_SRC optee/linux/enclave.c)
  else ()
    message(
      FATAL_ERROR "OP-TEE is not yet supported on platforms other than Linux.")
  endif ()

  set(PLATFORM_FLAGS "")
endif ()

if (OE_SGX AND WIN32)
  # oedebugrt is accessed via a bridge on Win32 and need not be linked.
  list(APPEND PLATFORM_SDK_ONLY_SRC sgx/windows/debugrtbridge.c)

  # __oe_dispatch_ocall function must have debug symbols for debuggers to
  # stitch the ocall stack. Use /Z7 flag to embed the debugging information
  # in the object file. When a host application is built, the linker will
  # extract this debugging information and put it in the pdb for the host
  # application. Using /Z7 avoids having to distribut oehost.pdb.
  # Note: This is a temporary fix and debuggers will not have this requirement
  # when ocall stack stitching is also done via the debugger contract.
  set_source_files_properties(sgx/calls.c PROPERTIES COMPILE_FLAGS "/Z7")
endif ()

# Common host verification files that work on any OS/architecture.
list(
  APPEND
  PLATFORM_HOST_ONLY_SRC
  ../common/attest_plugin.c
  ../common/datetime.c
  ../common/safecrt.c
  ../common/sha.c
  hexdump.c
  dupenv.c
  fopen.c
  tests.c
  result.c
  traceh.c)

# Common files that are used in the OE SDK only.
list(
  APPEND
  PLATFORM_SDK_ONLY_SRC
  ../common/kdf.c
  ../common/argv.c
  asym_keys.c
  calls.c
  ocalls.c
  error.c
  files.c
  fopen.c
  memalign.c
  signkey.c
  strings.c
  traceh_enclave.c)

# Combine the following common code along with the platform specific code and
# host verification code to get the full oehost target provided by the OE SDK.
add_library(oehost STATIC ${PLATFORM_HOST_ONLY_SRC} ${PLATFORM_SDK_ONLY_SRC})

add_library(oehostverify STATIC ${PLATFORM_HOST_ONLY_SRC})

target_link_libraries(oehostverify PUBLIC oe_includes)
target_link_libraries(oehost PUBLIC oe_includes)

if (OE_SGX)
  target_include_directories(
    oehost PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/sgxsdk/include)
endif ()

if (WIN32)
  target_link_libraries(oehost PUBLIC ws2_32 shlwapi)
endif ()

if (OE_SGX AND UNIX)
  # Link oedebugrt static library.
  target_link_libraries(oehost PRIVATE oedebugrt)

  # enter.c must be forced to retain the frame-pointer
  # for ocall stack-stitching by using the -fno-omit-frame-pointer flag.
  # It is compiled with -O2 flag to retain the same generated assembly
  # code in both debug and release builds.
  set_source_files_properties(
    oehost sgx/enter.c PROPERTIES COMPILE_FLAGS "-O2 -fno-omit-frame-pointer")
endif ()

add_dependencies(oehost syscall_untrusted_edl)
add_dependencies(oehost core_untrusted_edl)
if (OE_SGX)
  add_dependencies(oehost platform_untrusted_edl)
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
  target_link_libraries(oehost PRIVATE openenclave::crypto openenclave::dl
                                       Threads::Threads)
  target_link_libraries(oehostverify PRIVATE openenclave::crypto
                                             openenclave::dl Threads::Threads)

  if (OE_TRUSTZONE)
    target_include_directories(oehost PRIVATE ${OE_TZ_OPTEE_CLIENT_INC})
    target_link_libraries(oehost PRIVATE teec)
  endif ()
elseif (WIN32)
  target_include_directories(
    oehost PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  # Synchronization library is needed for WaitOnAddress/WakeByAddress functions
  # used by switchless ocalls worker threads.
  target_link_libraries(oehost PRIVATE bcrypt Crypt32 Synchronization)
  target_include_directories(
    oehostverify PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls/include)
  target_link_libraries(oehostverify PRIVATE bcrypt Crypt32)

  # TODO: Handle TrustZone on Windows.
endif ()

# For including edge routines.
target_include_directories(oehost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (OE_SGX)
  if (NOT LIBPATHS)
    set(LIBPATHS "/usr")
  endif ()

  # Optionally link in DCAP library
  if (HAS_QUOTE_PROVIDER)
    if (WIN32)
      list(APPEND LIBPATHS
           ${NUGET_PACKAGE_PATH}/DCAP_Components/build/lib/native/Libraries)
      list(APPEND INCPATHS
           "${NUGET_PACKAGE_PATH}/DCAP_Components/build/Header Files")
    endif ()
    find_library(
      LIBSGX_QE
      NAMES sgx_dcap_ql
      HINTS ${LIBPATHS})
    if (NOT LIBSGX_QE)
      message(
        FATAL_ERROR
          "No quote provider library found, aborting! Set -DHAS_QUOTE_PROVIDER=OFF to ignore."
      )
    endif ()
    add_library(sgx_dcap_ql SHARED IMPORTED)
    if (WIN32)
      set_target_properties(
        sgx_dcap_ql
        PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${INCPATHS}"
                   IMPORTED_LOCATION $ENV{WINDIR}/System32 IMPORTED_IMPLIB
                                                           ${LIBSGX_QE})
    elseif (UNIX)
      set_target_properties(sgx_dcap_ql PROPERTIES IMPORTED_LOCATION
                                                   ${LIBSGX_QE})
    endif ()
    # In Windows, add sgx_dcap_ql headers to the include path.
    # In Linux, they are already available in /usr/include.
    if (WIN32)
      target_include_directories(oehost PRIVATE ${INCPATHS})
    endif ()
  endif ()
endif ()

# Compile definitions and options
target_compile_definitions(
  oehost
  PUBLIC # NOTE: This definition is public to the rest of our project's
         # targets, but should not yet be exposed to consumers of our
         # package.
         $<BUILD_INTERFACE:OE_API_VERSION=2>
  PRIVATE OE_BUILD_UNTRUSTED OE_REPO_BRANCH_NAME="${GIT_BRANCH}"
          OE_REPO_LAST_COMMIT="${GIT_COMMIT}")

if (USE_DEBUG_MALLOC)
  target_compile_definitions(oehost PRIVATE OE_USE_DEBUG_MALLOC)
endif ()

if (COMPILE_SYSTEM_EDL)
  target_compile_definitions(oehost PRIVATE OE_USE_BUILTIN_EDL)
endif ()

if (WITH_EEID)
  target_compile_definitions(oehost PRIVATE OE_WITH_EXPERIMENTAL_EEID)
endif ()

if (UNIX)
  target_compile_options(
    oehost
    PRIVATE -Wno-attributes -Wmissing-prototypes -fPIC ${PLATFORM_FLAGS}
    PUBLIC -fstack-protector-strong)
  target_compile_definitions(
    oehost
    PRIVATE _GNU_SOURCE
    PUBLIC $<$<NOT:$<CONFIG:debug>>:_FORTIFY_SOURCE=2>)
endif ()

if (CMAKE_C_COMPILER_ID MATCHES GNU)
  target_compile_options(oehost PRIVATE -Wjump-misses-init)
endif ()

# Use the same the compile options and definitions from oehost.
target_compile_options(
  oehostverify
  PRIVATE $<TARGET_PROPERTY:oehost,COMPILE_OPTIONS>
  INTERFACE $<TARGET_PROPERTY:oehost,INTERFACE_COMPILE_OPTIONS>)

target_compile_definitions(
  oehostverify
  PRIVATE $<TARGET_PROPERTY:oehost,COMPILE_DEFINITIONS>
  INTERFACE $<TARGET_PROPERTY:oehost,INTERFACE_COMPILE_DEFINITIONS>)

# TODO: Remove this hard coded output directory.
set_property(TARGET oehost PROPERTY ARCHIVE_OUTPUT_DIRECTORY
                                    ${OE_LIBDIR}/openenclave/host)

if (UNIX)
  target_link_libraries(oehost INTERFACE -Wl,-z,noexecstack)
  target_link_libraries(oehostverify INTERFACE -Wl,-z,noexecstack -rdynamic)
endif ()

# Install targets
install(
  TARGETS oehost
  EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host
          COMPONENT OEHOSTVERIFY)

install(
  TARGETS oehostverify
  EXPORT openenclave-targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/host
          COMPONENT OEHOSTVERIFY)

include(measure/CMakeLists.txt)
