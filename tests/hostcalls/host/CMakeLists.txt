add_executable(hostcallshost host.cpp)

target_link_libraries(hostcallshost oehostapp)

target_compile_options(hostcallshost PRIVATE
    -Wno-error=unused-but-set-variable
    -Wno-error=unused-variable
    )
