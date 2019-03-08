# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_subdirectory(host)

if (BUILD_ENCLAVES)
	add_subdirectory(enc)
endif()

# Run all tests. Also generate a report.
if (USE_LIBSGX)
  add_enclave_test(tests/report report_host report_enc)
  set_tests_properties(tests/report PROPERTIES SKIP_RETURN_CODE 2)

  # Attest generated report; but without creating any enclave.
  # We can verify reports with USE_LIBSGX, but we can't generate one, so
  # only do this test under the USE_LIBSGX define.
  add_enclave_test(tests/report_attestation_without_enclave report_host report_enc
    --attest-generated-report)
  set_tests_properties(tests/report_attestation_without_enclave PROPERTIES SKIP_RETURN_CODE 2)
endif()
