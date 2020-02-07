# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

# NOTE: This is set here so that both `libcxx` and `musl` can use it
# without setting it twice. This is necessary due to an odd dependency
# between the two targets. See their respective CMake files for more
# details.
set(LIBCXX_INCLUDES ${OE_INCDIR}/openenclave/libcxx)

add_subdirectory(libcxx)
add_subdirectory(libcxxrt)
add_subdirectory(libunwind)
add_subdirectory(musl)
add_subdirectory(mbedtls)
if (OE_TRUSTZONE)
  # EL: (ARM) Exception Level
  # GP: GlobalPlatform
  #
  # ARM TrustZone Trusted Applications (TAs) execute in S:EL0 and OP-TEE OS
  # executes in S:EL1. EL0 is where user-mode applications execute while EL1 is
  # where kernel-mode software runs. Effectively, TAs are secure, user-mode
  # programs while OP-TEE is a secure, kernel-mode OS. In typical fashion, the
  # latter provides services to the former via system calls.
  #
  # In the same way as a typical Windows program does not call NT system
  # services directly and a typical Linux program does not invoke Linux system
  # calls directly, TAs do not invoke OP-TEE system calls directly either.
  # Instead, Windows programs are written against the Win32 API, Linux programs
  # are written against the POSIX API, and TAs are written against the
  # GlobalPlatform TEE Internal API. This API is implemented by libutee, which
  # invokes OP-TEE OS system calls in turn where required.
  add_subdirectory(optee/libutee)

  # Similarly to Intel SGX enclaves, OP-TEE TAs do not execute of their own
  # volition (i.e. OP-TEE OS does not have a scheduler) [1]. Instead, either a
  # non-secure user-mode program running in NS:EL0 or a non-secure kernel-mode
  # driver running in NS:EL1 must decide it requires a service from a TA. To do
  # this, the client (or host) running in the non-secure world must transfer to
  # a TA a request specifying the function ID for the TA to execute, the
  # function's input parameters as well as a buffer for the function's output
  # parameters and result value. Non-secure clients do not set this up by hand.
  # Instead, they call into the GlobalPlatform TEE Client API which performs
  # function call marhsalling on their behalf. In this sense, while the Open
  # Enclave SDK is self-contained with regards to ECALLs and OCALLs for Intel
  # SGX enclaves, this is not the case for OP-TEE TAs and some of that work is
  # relegated to the GP TEE Client API. This API is implemented by libteec.
  #
  # [1] ARM TrustZone TAs may activate on their own via secure interrupts, i.e.
  #     interrupts handled by OP-TEE in the secure world and potentially handed
  #     off to a TA for processing.
  #
  # Normally, for NS:EL0 (i.e. non-secure user-mode programs) libteec is a
  # shared library and dynamically loaded by clients. If the developer is
  # building the Open Enclave SDK with CMAKE_SYSROOT set to, say, the output of
  # a Buildroot build and that build includes libteec as a dynamic library,
  # then we can use it. Otherwise, we build our own and link against it
  # statically, thereby including libteec in every Open Enclave host.
  find_library(LIBTEEC NAMES teec libteec)
  if (LIBTEEC)
    add_library(teec SHARED IMPORTED)
    set_target_properties(teec PROPERTIES
      IMPORTED_LOCATION ${LIBTEEC})
  else ()
    set(OPTEE_CLIENT_DIR ${CMAKE_CURRENT_BINARY_DIR}/optee_client)

    include(ExternalProject)
    ExternalProject_Add(optee_client-wrap
      SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/optee_client
      DOWNLOAD_COMMAND
        ${CMAKE_COMMAND} -E copy_directory
          ${OE_TZ_OPTEE_CLIENT_SRC}
          ${OPTEE_CLIENT_DIR}
      UPDATE_COMMAND ""
      PATCH_COMMAND ""
      CMAKE_ARGS
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
      INSTALL_COMMAND ""
      BYPRODUCTS
        <BINARY_DIR>/libteec/libteec.a)

    set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
      ${CMAKE_CURRENT_BINARY_DIR}/optee_client
      ${CMAKE_BINARY_DIR}/libteec/libteec.a
    )
    ExternalProject_Get_property(optee_client-wrap SOURCE_DIR)
    ExternalProject_Get_property(optee_client-wrap BINARY_DIR)

    add_library(teec_imported STATIC IMPORTED)
    set_target_properties(teec_imported PROPERTIES
      IMPORTED_LOCATION ${BINARY_DIR}/libteec/libteec.a)

    add_library(teec INTERFACE)
    add_dependencies(teec optee_client-wrap)
    target_link_libraries(teec INTERFACE
      $<BUILD_INTERFACE:teec_imported>
      $<INSTALL_INTERFACE:$<INSTALL_PREFIX>/${CMAKE_INSTALL_LIBDIR}/openenclave/optee/libteec/libteec.a>)

    install(TARGETS teec EXPORT openenclave-targets)

    install(FILES ${BINARY_DIR}/libteec/libteec.a
      DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/optee/libteec)
  endif ()
endif ()
