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
        target_link_libraries(${ENCLAVE_TARGET} PRIVATE libutee)
        add_dependencies(${ENCLAVE_TARGET} oeedger8rtool)
    endif()
endfunction()

macro(add_enclave_ex)
    set(options CXX)
    set(oneValueArgs TARGET UUID CONFIG KEY)
    set(multiValueArgs SOURCES INCLUDES LIBRARIES)
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
        
        # Remove -rdynamic from linker flags.
        set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
        set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
        set(CMAKE_EXE_EXPORTS_C_FLAG)
        
        set(CMAKE_C_LINK_EXECUTABLE "${OE_TA_TOOLCHAIN_PREFIX}ld <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")
        set(CMAKE_CXX_LINK_EXECUTABLE "${OE_TA_TOOLCHAIN_PREFIX}ld <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>")

        # Generate linker script from template.
        set(C_PREPROCESSOR ${OE_TA_TOOLCHAIN_PREFIX}cpp)
        set(TA_LINKER_SCRIPT ${CMAKE_CURRENT_BINARY_DIR}/ta.ld)
        set(TA_LINKER_SCRIPT ${TA_LINKER_SCRIPT} PARENT_SCOPE)
        add_custom_target(${ENCLAVE_UUID}.ld
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

        set(ENCLAVE_C_SOURCES   ${ENCLAVE_SOURCES})
        set(ENCLAVE_CPP_SOURCES ${ENCLAVE_SOURCES})

        list(FILTER ENCLAVE_C_SOURCES   EXCLUDE REGEX "\\.cc$")
        list(FILTER ENCLAVE_C_SOURCES   EXCLUDE REGEX "\\.cpp$")
        list(FILTER ENCLAVE_C_SOURCES   EXCLUDE REGEX "\\.cxx$")

        list(FILTER ENCLAVE_CPP_SOURCES EXCLUDE REGEX "\\.c$")

        add_library(${ENCLAVE_TARGET}-c OBJECT ${ENCLAVE_C_SOURCES})
        set_property(TARGET ${ENCLAVE_TARGET}-c PROPERTY C_STANDARD 99)
        target_include_directories(${ENCLAVE_TARGET}-c
            BEFORE PRIVATE
                ${ENCLAVE_INCLUDES}
                ${CMAKE_CURRENT_BINARY_DIR}
                ${CMAKE_CURRENT_SOURCE_DIR}/optee)
        target_link_libraries(${ENCLAVE_TARGET}-c
            PRIVATE
                oecore
                mbedx509_enc mbedcrypto_enc
                oelibc)
        target_compile_options(${ENCLAVE_TARGET}-c BEFORE PUBLIC
            -DOE_NO_POSIX_SOCKET_API
            -DOE_NO_WINSOCK_API
            -DOE_NO_POSIX_FILE_API)

        if(ENCLAVE_CXX)
            add_library(${ENCLAVE_TARGET}-cpp OBJECT ${ENCLAVE_CPP_SOURCES})
            set_property(TARGET ${ENCLAVE_TARGET}-cpp PROPERTY C_STANDARD 99)
            target_include_directories(${ENCLAVE_TARGET}-cpp
                BEFORE PRIVATE
                    ${ENCLAVE_INCLUDES}
                    ${CMAKE_CURRENT_BINARY_DIR}
                    ${CMAKE_CURRENT_SOURCE_DIR}/optee)
            target_link_libraries(${ENCLAVE_TARGET}-cpp
                PRIVATE
                    oecore
                    mbedx509_enc mbedcrypto_enc
                    oelibcxx oelibc)
            target_compile_options(${ENCLAVE_TARGET}-cpp
                BEFORE PUBLIC
                    -DOE_NO_POSIX_SOCKET_API
                    -DOE_NO_WINSOCK_API
                    -DOE_NO_POSIX_FILE_API)
        endif()

        add_executable(${ENCLAVE_TARGET})
        set_property(TARGET ${ENCLAVE_TARGET} PROPERTY C_STANDARD 99)
        set_target_properties(${ENCLAVE_TARGET} PROPERTIES SUFFIX ".elf")
        add_dependencies(${ENCLAVE_TARGET} oeedger8rtool ${ENCLAVE_UUID}.ld)
        if(ENCLAVE_CXX)
            target_link_libraries(${ENCLAVE_TARGET} ${ENCLAVE_TARGET}-cpp)
        endif()
        target_link_libraries(${ENCLAVE_TARGET} ${ENCLAVE_TARGET}-c)
        if(ENCLAVE_LIBRARIES)
            target_link_libraries(${ENCLAVE_TARGET} ${ENCLAVE_LIBRARIES})
        endif()
        target_link_libraries(${ENCLAVE_TARGET} oecore mbedx509_enc mbedcrypto_enc oelibcxx oelibc)

        # Strip unneeded bits.
        set(OBJCOPY ${OE_TA_TOOLCHAIN_PREFIX}objcopy)
        add_custom_target(${ENCLAVE_UUID}.stripped.elf
            COMMAND
                ${OBJCOPY}
                    --strip-unneeded $<TARGET_FILE:${ENCLAVE_TARGET}>
                    $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
            BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf)
        add_dependencies(${ENCLAVE_UUID}.stripped.elf ${ENCLAVE_TARGET})

        # Sign the TA with the default key.
        # TODO: Allow selection of key.
        add_custom_target(${ENCLAVE_UUID}.ta
            COMMAND
                ${OE_TA_DEV_KIT_SIGN_TOOL}
                    --key ${OE_TA_DEV_KIT_DEFAULT_SIGNING_KEY}
                    --uuid ${ENCLAVE_UUID}
                    --version 0
                    --in $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.stripped.elf
                    --out $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta
            BYPRODUCTS $<TARGET_FILE_DIR:${ENCLAVE_TARGET}>/${ENCLAVE_UUID}.ta)
        add_dependencies(${ENCLAVE_UUID}.ta ${ENCLAVE_UUID}.stripped.elf)

        # Set linker options.
        # NOTE: This has to be at the end, apparently:
        #       https://gitlab.kitware.com/cmake/cmake/issues/17210
        set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
        set(CMAKE_EXE_LINKER_FLAGS "${OE_TA_LD_FLAGS} -T ${TA_LINKER_SCRIPT} -L${LIBGCC_PATH}")
        if(ENCLAVE_CXX)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --eh-frame-hdr")
        endif()
    endif()
endmacro(add_enclave_ex)
