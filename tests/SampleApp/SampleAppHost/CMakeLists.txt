add_executable(SampleAppHost CallWrappers.cpp SampleAppHost.cpp)

target_link_libraries(SampleAppHost oehost)

target_compile_options(SampleAppHost PRIVATE -Wall -Werror)
target_link_libraries(SampleAppHost -rdynamic)
