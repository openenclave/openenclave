# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro(add_enclave)
  set(options CXX)
  set(oneValueArgs TARGET UUID CONFIG KEY)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(ENCLAVE
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN})

  if(OE_SGX)
    add_enclave_sgx(
      CXX ${ENCLAVE_CXX}
      TARGET ${ENCLAVE_TARGET}
      CONFIG ${ENCLAVE_CONFIG}
      KEY ${ENCLAVE_KEY}
      SOURCES ${ENCLAVE_SOURCES})
  elseif(OE_OPTEE)
    add_enclave_optee(
      CXX ${ENCLAVE_CXX}
      TARGET ${ENCLAVE_TARGET}
      UUID ${ENCLAVE_UUID}
      KEY ${ENCLAVE_KEY}
      SOURCES ${ENCLAVE_SOURCES})
  endif()
endmacro()

function(add_enclave_sgx)
  set(options CXX)
  set(oneValueArgs TARGET CONFIG KEY)
  set(multiValueArgs SOURCES)
  cmake_parse_arguments(ENCLAVE
    "${options}"
    "${oneValueArgs}"
    "${multiValueArgs}"
    ${ARGN})

  if(WIN32)
    maybe_build_using_clangw(enclave)
  endif()

  add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
  target_compile_definitions(${ENCLAVE_TARGET} PUBLIC OE_API_VERSION=2)
  target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(${ENCLAVE_TARGET} openenclave::oeenclave openenclave::oelibc)

  add_custom_command(OUTPUT ${ENCLAVE_TARGET}-private.pem ${ENCLAVE_TARGET}-public.pem
    COMMAND openssl genrsa -out ${ENCLAVE_TARGET}-private.pem -3 3072
    COMMAND openssl rsa -in ${ENCLAVE_TARGET}-private.pem -pubout -out ${ENCLAVE_TARGET}-public.pem)

  add_custom_command(OUTPUT ${ENCLAVE_TARGET}.signed
    DEPENDS ${ENCLAVE_TARGET} ${ENCLAVE_TARGET}.conf ${ENCLAVE_TARGET}-private.pem
    COMMAND openenclave::oesign sign -e $<TARGET_FILE:${ENCLAVE_TARGET}> -c ${CMAKE_CURRENT_SOURCE_DIR}/${ENCLAVE_TARGET}.conf -k ${ENCLAVE_TARGET}-private.pem)

  add_custom_target(sign ALL DEPENDS ${ENCLAVE_TARGET}.signed)
endfunction()

macro(add_enclave_optee)
   set(options CXX)
   set(oneValueArgs TARGET UUID KEY)
   set(multiValueArgs SOURCES)
   cmake_parse_arguments(ENCLAVE
     "${options}"
     "${oneValueArgs}"
     "${multiValueArgs}"
     ${ARGN})

  # Set up the linker flags exactly as we need them such that the resulting
  # binary be compatible with OP-TEE's loader.
  set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
  set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
  set(CMAKE_EXE_EXPORTS_C_FLAG)

  string(REPLACE "gcc" "ld" LINKER ${CMAKE_C_COMPILER})
  set(CMAKE_C_LINK_EXECUTABLE "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> <LINK_LIBRARIES> -lgcc -o <TARGET>")
  set(CMAKE_CXX_LINK_EXECUTABLE "${LINKER} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> <LINK_LIBRARIES> -lgcc -o <TARGET>")

  # Generate linker script from template.
  string(REPLACE "gcc" "cpp" C_PREPROCESSOR ${CMAKE_C_COMPILER})
  set(TA_LINKER_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/ta.ld)
  add_custom_target(${ENCLAVE_TARGET}.ld
    COMMAND
      ${C_PREPROCESSOR} -Wp,-P -DASM=1 -DARM64 -nostdinc ${OE_PACKAGE_PREFIX}/ta.ld.S > ${TA_LINKER_SCRIPT}
    SOURCES ${OE_PACKAGE_PREFIX}/ta.ld.S
    DEPENDS ${OE_PACKAGE_PREFIX}/ta.ld.S
    BYPRODUCTS ${TA_LINKER_SCRIPT})

  # Ask GCC where is libgcc.
  execute_process(
    COMMAND ${CMAKE_C_COMPILER}
      -print-libgcc-file-name
    OUTPUT_VARIABLE LIBGCC_PATH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  get_filename_component(LIBGCC_PATH ${LIBGCC_PATH} DIRECTORY)

  # Set up the target.
  add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
  set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES OUTPUT_NAME ${ENCLAVE_UUID})
  set_target_properties(${ENCLAVE_TARGET} PROPERTIES SUFFIX ".elf")
  add_dependencies(${ENCLAVE_TARGET} ${ENCLAVE_TARGET}.ld)
  target_include_directories(${ENCLAVE_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
  target_link_libraries(${ENCLAVE_TARGET} openenclave::oeenclave)
  if(ENCLAVE_CXX)
    target_link_libraries(${ENCLAVE_TARGET} openenclave::oelibcxx)
  endif()

  # Strip unneeded bits.
  string(REPLACE "gcc" "objcopy" OBJCOPY ${CMAKE_C_COMPILER})
  add_custom_target(${ENCLAVE_TARGET}.stripped.elf
    COMMAND
      ${OBJCOPY}
        --strip-unneeded $<TARGET_FILE:${ENCLAVE_TARGET}>
        $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
    BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf)
  add_dependencies(${ENCLAVE_TARGET}.stripped.elf ${ENCLAVE_TARGET})

  # Sign the TA with the given key, or with the default key if none was given.
  if(NOT ENCLAVE_KEY)
    set(ENCLAVE_KEY ${OE_PACKAGE_PREFIX}/default_ta.pem)
  endif()
  add_custom_target(${ENCLAVE_TARGET}.ta ALL
    COMMAND
      ${OE_PACKAGE_PREFIX}/sign.py
        --key ${ENCLAVE_KEY}
        --uuid ${ENCLAVE_UUID}
        --version 0
        --in $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
        --out $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta
    BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta)
  add_dependencies(${ENCLAVE_TARGET}.ta ${ENCLAVE_TARGET}.stripped.elf)

  # Set linker options.
  # NOTE: This has to be at the end, apparently:
  #       https://gitlab.kitware.com/cmake/cmake/issues/17210
  set(CMAKE_EXE_LINKER_FLAGS "-T ${TA_LINKER_SCRIPT} -L${LIBGCC_PATH} --entry=_start")
  if(ENCLAVE_CXX)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --eh-frame-hdr")
  endif()
endmacro()
