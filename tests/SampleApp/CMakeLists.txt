add_subdirectory(SampleApp)
add_subdirectory(SampleAppHost)

add_test(tests/SampleApp SampleAppHost/SampleAppHost SampleApp/SampleApp.signed.so)
