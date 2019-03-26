function(add_enclave_library_ex)
    set(options CXX)
    set(oneValueArgs TARGET UUID CONFIG KEY)
    set(multiValueArgs SOURCES C_GEN LIBRARIES)
    cmake_parse_arguments(ENCLAVE
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    if(UNIX AND TZ AND (NOT OE_USE_TA_DEV_KIT))
        set(CMAKE_ASM_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}gcc)
        set(CMAKE_C_COMPILER   ${OE_TA_TOOLCHAIN_PREFIX}gcc)
        set(CMAKE_CXX_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}g++)

        add_library(${ENCLAVE_TARGET} STATIC ${ENCLAVE_SOURCES})
        set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
        target_link_libraries(${ENCLAVE_TARGET} PUBLIC libutee)
        add_dependencies(${ENCLAVE_TARGET} oeedger8rtool)
    endif()
endfunction()

macro(add_enclave_ex)
    set(options CXX)
    set(oneValueArgs TARGET UUID CONFIG KEY)
    set(multiValueArgs SOURCES C_GEN LIBRARIES)
    cmake_parse_arguments(ENCLAVE
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    if(TZ)
        set(ENCLAVE_TARGET ${ENCLAVE_UUID})
    endif()

    if(UNIX AND TZ AND (NOT OE_USE_TA_DEV_KIT))
        set(CMAKE_ASM_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}gcc)
        set(CMAKE_C_COMPILER   ${OE_TA_TOOLCHAIN_PREFIX}gcc)
        set(CMAKE_CXX_COMPILER ${OE_TA_TOOLCHAIN_PREFIX}g++)
        set(CMAKE_C_LINK_EXECUTABLE "${OE_TA_TOOLCHAIN_PREFIX}ld <FLAGS> <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

        # Generate linker script from template.
        set(C_PREPROCESSOR ${OE_TA_TOOLCHAIN_PREFIX}cpp)
        set(TA_LINKER_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/ta.ld)
        set(TA_LINKER_SCRIPT ${TA_LINKER_SCRIPT} PARENT_SCOPE)
        add_custom_target(${ENCLAVE_TARGET}-ld
            COMMAND
                ${C_PREPROCESSOR} -Wp,-P -DASM=1 -DARM64 -nostdinc ${OE_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE} > ${TA_LINKER_SCRIPT}
            SOURCES ${OE_TA_DEV_KIT_LINKER_SCRIPT_TEMPLATE}
            BYPRODUCTS ${TA_LINKER_SCRIPT})

        # Ask GCC where is libgcc.
        execute_process(
            COMMAND ${CMAKE_C_COMPILER}
                ${OE_TA_C_FLAGS}
                -print-libgcc-file-name
            OUTPUT_VARIABLE LIBGCC_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        get_filename_component(LIBGCC_PATH ${LIBGCC_PATH} DIRECTORY)
    
        # Set up the target.
        list(APPEND ENCLAVE_SOURCES ${OE_TA_DEV_KIT_HEADER_SOURCE})
        add_executable(${ENCLAVE_TARGET} ${ENCLAVE_SOURCES})
        set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
        target_include_directories(${ENCLAVE_TARGET}
            BEFORE PRIVATE
                ${CMAKE_CURRENT_BINARY_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/optee)
        target_link_libraries(${ENCLAVE_TARGET} PUBLIC liboestdio_enc oeenclave mbedx509_enc mbedcrypto_enc libc libutee gcc)
        add_dependencies(${ENCLAVE_TARGET} oeedger8rtool ${ENCLAVE_TARGET}-ld)

        # Strip unneeded bits.
        set(OBJCOPY ${OE_TA_TOOLCHAIN_PREFIX}objcopy)
        add_custom_target(${ENCLAVE_TARGET}-stripped
            COMMAND
                ${OBJCOPY}
                    --strip-unneeded $<TARGET_FILE:${ENCLAVE_TARGET}>
                    $<TARGET_FILE:${ENCLAVE_TARGET}>.stripped
            BYPRODUCTS $<TARGET_FILE:${ENCLAVE_TARGET}>.stripped)

        # Sign the TA with the default key.
        # TODO: Allow selection of key.
        STRING(REPLACE "elf" "ta" ENCLAVE_SIGNED $<TARGET_FILE:${ENCLAVE_TARGET}>)
        add_custom_target(${ENCLAVE_TARGET}-signed
            COMMAND
                ${OE_TA_DEV_KIT_SIGN_TOOL}
                    --key ${OE_TA_DEV_KIT_DEFAULT_SIGNING_KEY}
                    --uuid ${ENCLAVE_UUID}
                    --version 0
                    --in $<TARGET_FILE:${ENCLAVE_TARGET}>.stripped
                    --out $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta
            BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta)
        add_dependencies(${ENCLAVE_TARGET}-signed ${ENCLAVE_TARGET}-stripped)

        # Set linker options.
        # NOTE: This has to be at the end, apparently:
        #       https://gitlab.kitware.com/cmake/cmake/issues/17210
        set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
        set(CMAKE_EXE_LINKER_FLAGS "${OE_TA_LD_FLAGS} -T ${TA_LINKER_SCRIPT} -L${LIBGCC_PATH}")
    endif()
endmacro(add_enclave_ex)
