add_executable(oesign main.c)

target_link_libraries(oesign oehost)

# assemble into proper collector dir
set_property(TARGET oesign PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install (TARGETS oesign DESTINATION ${CMAKE_INSTALL_BINDIR})
