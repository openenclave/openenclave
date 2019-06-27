# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cp create-errors/enc/*.ta /lib/optee_armtz || exit 1
cp crypto/enclave/enc/*.ta /lib/optee_armtz || exit 1
cp hexdump/enc/*.ta /lib/optee_armtz || exit 1
cp hostcalls/enc/*.ta /lib/optee_armtz || exit 1
cp initializers/enc/*.ta /lib/optee_armtz || exit 1
cp mixed_c_cpp/enc/*.ta /lib/optee_armtz || exit 1
cp pingpong/enc/*.ta /lib/optee_armtz || exit 1
cp pingpong-shared/enc/*.ta /lib/optee_armtz || exit 1
cp safecrt/enc/*.ta /lib/optee_armtz || exit 1

export OE_SIMULATION=1

cd create-errors/host
./create_errors_host 1083bbac-751e-4d26-ada6-c254bbfbe653 || exit 1
cd ../..

cd crypto/enclave
./host/cryptohost f0be7db0-ce7c-4dc4-b8c8-b161f4216225 || exit 1
cd ../..

cd hexdump/host
./hexdump_host 126830b9-eb9f-412a-89a7-bcc8a517c12e || exit 1
cd ../..

cd hostcalls/host
./hostcalls_host 60814a64-61e9-4fd9-9159-e158d73f6a2e || exit 1
cd ../..

cd initializers/host
./initializers_host 62f73b00-bdfe-4763-a06a-dc561a3a34d8 || exit 1
cd ../..

cd mixed_c_cpp/host
./mixed_c_cpp_host 952c55c8-59f3-47a0-814c-ae3276a9808f || exit 1
cd ../..

cd pingpong/host
./pingpong_host 0a6cbbd3-160a-4c86-9d9d-c9cf1956be16 || exit 1
cd ../..

cd pingpong-shared/host
LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PWD ./pingpong-shared_host e229cc0f-3199-4ad3-91a7-47906fcbcc59 || exit 1
cd ../..

cd safecrt/host
./safecrt_host 91dc6667-7a33-4bbc-ab3e-ab4fca5215b7 || exit 1
cd ../..
