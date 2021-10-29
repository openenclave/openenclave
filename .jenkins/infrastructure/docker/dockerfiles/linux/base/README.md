# Open Enclave Base Docker Image

This Docker image provides a minimal Ubuntu environment that can run Open Enclave applications.

Please note the purpose of this image is not to build Open Enclave applications.

## Mounting the Intel SGX devices
This image will require access to the Intel SGX devices. It will depend on the Intel SGX driver version you are running on your host system. 

For Intel SGX driver 1.36.2 and lower, the following parameter is needed:  
  ```--device /dev/sgx:/dev/sgx```  

For Intel SGX driver 1.41 and above, the following parameters are needed:  
  ```--device /dev/sgx/provision:/dev/sgx/provision```  
  ```--device /dev/sgx/enclave:/dev/sgx/enclave```

## Out-of-proc attestation support
This image supports out-of-proc attestation using Intel SGX. To allow this, the Intel SGX AESM Service will need to be made available by running the container with the following parameters:  
   ```--volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket```  
   ```--env SGX_AESM_ADDR=1```

## Versions

All base images available are:  
[oeciteam/openenclave-base-ubuntu-18.04](https://hub.docker.com/r/oeciteam/openenclave-base-ubuntu-18.04) for Ubuntu 18.04  
[oeciteam/openenclave-base-ubuntu-20.04](https://hub.docker.com/r/oeciteam/openenclave-base-ubuntu-20.04) for Ubuntu 20.04

The base Docker images can be pulled from Dockerhub like so:
```docker pull oeciteam/openenclave-base-ubuntu-18.04```

Tags are versioned by the Intel SGX version that are used to build it. For example: `SGX-2.15.100`.
Alternatively, you can use the `latest` tag to pull in the container with the latest Intel SGX version. 
