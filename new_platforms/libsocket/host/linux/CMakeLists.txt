include(oeedl_file)

oeedl_file(../../../../include/openenclave/socket.edl host gen)

add_library(liboesocket_host STATIC socket_host.c ${gen})

target_include_directories(liboesocket_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(liboesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_include_directories(liboesocket_host PRIVATE ${PROJECT_SOURCE_DIR}/../include)
