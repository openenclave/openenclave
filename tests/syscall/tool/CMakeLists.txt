# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

if (WIN32)
    set(SRC rmdir_win32.c)
else ()
    set(SRC rmdir_linux.c)
endif ()

add_library(rmdir STATIC ${SRC})
if (WIN32)
    target_link_libraries(rmdir PUBLIC Shell32)
endif ()

if(UNIX)
    set_source_files_properties(${SRC}
        PROPERTIES
        COMPILE_FLAGS " -Wno-unused-parameter")
endif()
