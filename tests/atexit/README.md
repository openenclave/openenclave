This directory tests enclave with atexit:
1. Atexit triggers one ocall;
2. Atexit triggers multiple ocalls;
3. It cannot do ecall in ocall triggerred by atexit.
