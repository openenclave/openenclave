macro(compileAsC99)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_C_FLAGS "--std=c99 ${CMAKE_C_FLAGS}")
      set (CMAKE_CXX_FLAGS "--std=c++11 ${CMAKE_CXX_FLAGS}")
    endif()
  else()
    set (CMAKE_C_STANDARD 99)
    set (CMAKE_CXX_STANDARD 11)
  endif()
endmacro(compileAsC99)

compileAsC99()

set(AZUREIOT_INC_FOLDER "/usr/include/azureiot" "/usr/include/azureiot/inc")
include_directories(${AZUREIOT_INC_FOLDER})
set(c_files host.c main.c)

include(oeedl_file)
include(add_host)

set(TARGET [[project-name]])

oeedl_file(../[[project-name]].edl host GEN C_GEN H_GEN ${OE_PATH}/include)

add_host(
    TARGET ${TARGET}
    SOURCES main.c host.c ${GEN})

set(AZUREIOT_LIB_FOLDER "/usr/lib/arm-linux-gnueabihf")
find_library(CURL_LIBRARY curl HINTS ${AZUREIOT_LIB_FOLDER})
find_library(M_LIBRARY m HINTS ${AZUREIOT_LIB_FOLDER})
find_library(SSL_LIBRARY ssl HINTS ${AZUREIOT_LIB_FOLDER})
find_library(CRYPTO_LIBRARY crypto HINTS ${AZUREIOT_LIB_FOLDER})
find_library(UUID_LIBRARY uuid HINTS ${AZUREIOT_LIB_FOLDER})
find_library(DL_LIBRARY dl HINTS ${AZUREIOT_LIB_FOLDER})
target_link_libraries(${TARGET}
    iothub_client_mqtt_transport
    iothub_client
    parson
    umqtt
    prov_auth_client
    hsm_security_client
    uhttp
    aziotsharedutil
    pthread
    ${CURL_LIBRARY}
    ${M_LIBRARY}
    ${SSL_LIBRARY}
    ${CRYPTO_LIBRARY}
    ${UUID_LIBRARY}
    ${DL_LIBRARY}
)
