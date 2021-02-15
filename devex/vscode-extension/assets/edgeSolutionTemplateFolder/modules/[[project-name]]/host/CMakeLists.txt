# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

macro (compileAsC99)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set(CMAKE_C_FLAGS "--std=c99 ${CMAKE_C_FLAGS}")
      set(CMAKE_CXX_FLAGS "--std=c++11 ${CMAKE_CXX_FLAGS}")
    endif ()
  else ()
    set(CMAKE_C_STANDARD 99)
    set(CMAKE_CXX_STANDARD 11)
  endif ()
endmacro (compileAsC99)

compileasc99()

set(AZUREIOT_INC_FOLDER "/usr/include/azureiot" "/usr/include/azureiot/inc")
include_directories(${AZUREIOT_INC_FOLDER})

add_custom_command(
  OUTPUT
    [[project-name]]_u.h
    [[project-name]]_u.c
    [[project-name]]_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/[[project-name]].edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/[[project-name]].edl)

add_executable([[project-name]]
    host.c
    main.c
    ${CMAKE_CURRENT_BINARY_DIR}/[[project-name]]_u.c)

target_compile_definitions([[project-name]] PRIVATE USE_EDGE_MODULES)

target_include_directories([[project-name]] PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries([[project-name]] openenclave::oehost)

set(AZUREIOT_LIB_FOLDER "/usr/lib/aarch64-linux-gnu")
find_library(CURL_LIBRARY curl HINTS ${AZUREIOT_LIB_FOLDER})
find_library(M_LIBRARY m HINTS ${AZUREIOT_LIB_FOLDER})
find_library(SSL_LIBRARY ssl HINTS ${AZUREIOT_LIB_FOLDER})
find_library(CRYPTO_LIBRARY crypto HINTS ${AZUREIOT_LIB_FOLDER})
find_library(UUID_LIBRARY uuid HINTS ${AZUREIOT_LIB_FOLDER})
find_library(DL_LIBRARY dl HINTS ${AZUREIOT_LIB_FOLDER})
target_link_libraries(
  [[project-name]]
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
  ${DL_LIBRARY})
