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
        target_link_libraries(${ENCLAVE_TARGET} PUBLIC
            libutee libc)
        add_dependencies(${ENCLAVE_TARGET} oeedger8rtool)
    endif()
endfunction()

function(add_enclave_ex)
    set(oneValueArgs TARGET UUID)
    set(multiValueArgs SOURCES LIBRARIES)
    cmake_parse_arguments(ENCLAVE
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    if(UNIX AND TZ AND (NOT OE_USE_TA_DEV_KIT))
        # TODO: Set up linker and signing.
    endif()
endfunction(add_enclave_ex)
