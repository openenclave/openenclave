add_executable(oesgx oesgx.c)

target_compile_options(oesgx PRIVATE  -Wall -O2)

# assemble into proper collector dir
set_property(TARGET oesgx PROPERTY RUNTIME_OUTPUT_DIRECTORY ${OE_BINDIR})

# install rule
install (TARGETS oesgx DESTINATION ${CMAKE_INSTALL_BINDIR})

