add_executable(oegen
    files.cpp
    generator.cpp
    lexer.cpp
    main.cpp
    objects.cpp
    parser.cpp
    types.cpp
    )

target_link_libraries(oegen oehost)

# assemble into proper collector dir
set_property(TARGET oegen PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install (TARGETS oegen EXPORT openenclave DESTINATION ${CMAKE_INSTALL_BINDIR})

