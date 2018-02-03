add_library(oeenclave STATIC
    assert.c
    atexit.c
    calls.c
    globals.c
    hostcalls.c
    hoststack.c
    init.c
    jump.c
    memory.c
    once.c
    report.c
    result.c
    sbrk.c
    snprintf.c
    spinlock.c
    string.c
    td.c
    thread.c
    abort.S
    exit.S
    main.S
    )

target_link_libraries(oeenclave PUBLIC oe_includes)

target_compile_options(oeenclave PUBLIC
    -m64 -fPIC
    -nostdinc
    $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>
    -fno-stack-protector -fvisibility=hidden
    )

# addl link-options for enclave apps
target_link_libraries(oeenclave INTERFACE
    -nostdlib -nodefaultlibs -nostartfiles
    -Wl,--no-undefined,-Bstatic,-Bsymbolic,--export-dynamic,-pie,-eOE_Main
    )

# jump.s must be optimized for the correct call-frame.
set_source_files_properties(jump.c PROPERTIES COMPILE_FLAGS -O2)

target_compile_definitions(oeenclave PRIVATE -DOE_BUILD_ENCLAVE)

set_property(TARGET oeenclave PROPERTY ARCHIVE_OUTPUT_DIRECTORY ${OE_LIBDIR}/openenclave/enclave)
install (TARGETS oeenclave EXPORT openenclave ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/openenclave/enclave)
