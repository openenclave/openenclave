add_subdirectory(SampleAppCRT)
add_subdirectory(SampleAppCRTHost)

add_test(tests/SampleAppCRT SampleAppCRTHost/SampleAppCRTHost SampleAppCRT/SampleAppCRT.signed.so)
