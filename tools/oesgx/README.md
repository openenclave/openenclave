oesgx
=====

This directory contains the oesgx tool, which determines if the CPU and BIOS support Intel SGX.
If the platform supports Intel SGX, it prints if Flexible Launch Control (FLC) is supported,
SGX1/SGX2, 64-bit support for enclaves, the Max Enclave Size and Enclave Page Cache (EPC) size
on the platform.

For example:

$ /opt/openenclave/bin/oesgx
CPU supports SGX_FLC:Flexible Launch Control
CPU supports Software Guard Extensions:SGX1
MaxEnclaveSize_64: 2^(36)
EPC size on the platform: 41943040
