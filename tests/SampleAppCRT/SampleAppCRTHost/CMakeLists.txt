add_executable(SampleAppCRTHost SampleAppCRTHost.cpp)

target_link_libraries(SampleAppCRTHost oehost)

target_compile_options(SampleAppCRTHost PRIVATE -Wall -Werror)
target_link_libraries(SampleAppCRTHost -rdynamic)
