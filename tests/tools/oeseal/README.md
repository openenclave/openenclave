oeseal
=====

oeseal is an internal debugging tool for the SGX sealing API, which supports
the following features. Currently the tool only supports Linux.

- Seal

  Seal the content of an input file and optionally write the sealed date to a file.

  Example:
  ```sh
  host/oeseal seal --enclave enc/sgx_oeseal_enc --input testfile --output sealed_output
  ```

- Unseal

  Unseal the data that was sealed by the tool and optionally write the result to a file.

  Example:
  ```sh
  host/oeseal unseal --enclave enc/sgx_oeseal_enc --input sealed_output --output unsealed_output
  ```

- Check the SGX key_request data structure

  Dump the SGX key_request data structure included in the sealed data. The structure
  is used to derive the sealing key.

  Example:
  ```sh
  host/oeseal seal --enclave enc/sgx_oeseal_enc --input testfile --output sealed_output --verbose
  ```
  or
  ```sh
  host/oeseal unseal --enclave enc/sgx_oeseal_enc --input sealed_output --output unsealed_output --verbose
  ```

See more information with `host/oeseal --help`
