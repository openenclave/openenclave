add_library(oe_includes INTERFACE)

target_include_directories(oe_includes INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

install (DIRECTORY openenclave DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
