oeedl_file(../oetests.edl enclave GEN C_GEN H_GEN ${OE_PATH}/include)

set(SRCS
    oetests_enclave.c
    OETestTA.c)

if(WIN32 AND SGX)
    add_library(oetests_enclave MODULE ${SRCS} ${GEN})

    target_include_directories(oetests_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(oetests_enclave oeenclave oesocket_enc oestdio_enc)

    target_link_options(oetests_enclave BEFORE PRIVATE "/NODEFAULTLIB")
    target_link_options(oetests_enclave BEFORE PRIVATE "/NOENTRY")
    target_link_options(oetests_enclave BEFORE PRIVATE "/MANIFEST:NO")

    string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
endif()
