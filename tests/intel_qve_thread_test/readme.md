# oe_verify_evidence multi-thread performance test

This test will spawn multiple enclave threads, each calls `ov_verify_evidence` in a loop for a given duration to test its performance.

The evidence can be in SGX ECDSA or TDX format.

## Usage

```bash
./intel_qve_thread_test <intel_qve_thread_test_enc file>
                        <SGX/TDX evidence file> <format, one of sgx/tdx>
                        <number of enclave thread> <duration of the loop (in sec)>
```

## Run the test
```bash
# You can run this test using ctest
ctest -R intel --verbose

# Or directly run the binary
cd tests/intel_qve_thread_test && ./intel_qve_thread_test intel_qve_thread_test_enc.signed ../../../tests/intel_qve_thread_test/data/tdx_quote tdx 8 30
```

### Example output
```
$ ./intel_qve_thread_test intel_qve_thread_test_enc.signed ../../../tests/intel_qve_thread_test/data/tdx_quote tdx 8 30
Creating thread 0
Creating thread 1
Creating thread 2
Creating thread 3
Creating thread 4
Creating thread 5
Creating thread 6
Creating thread 7
Azure Quote Provider: libdcap_quoteprov.so [ERROR]: Could not retrieve environment variable for 'AZDCAP_DEBUG_LOG_LEVEL'
Thread 6 finished, OPS 0.9 (28 in 30 sec)
Thread 0 finished, OPS 0.9 (28 in 30 sec)
Thread 5 finished, OPS 0.9 (28 in 30 sec)
Thread 7 finished, OPS 0.9 (28 in 30 sec)
Thread 3 finished, OPS 0.9 (28 in 30 sec)
Thread 1 finished, OPS 0.9 (28 in 30 sec)
Thread 2 finished, OPS 0.9 (28 in 30 sec)
Thread 4 finished, OPS 0.9 (28 in 30 sec)
Overall OPS 7 (224 in 30 sec)
```