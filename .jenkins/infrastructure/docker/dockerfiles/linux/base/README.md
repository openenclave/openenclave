# Open Enclave Base Docker Image

This Docker image provides a minimal Ubuntu environment that can run Open Enclave applications.

Please note the purpose of this image is not to build Open Enclave applications.

## Mounting the Intel SGX devices
This image will require access to the Intel SGX devices. It will depend on the Intel SGX driver version you are running on your host system. 

For Intel SGX driver 1.36.2 and lower, the following parameter is needed:  
  ```--device /dev/sgx:/dev/sgx```  

For Intel SGX driver 1.41 and above, the following parameters are needed:  
  ```--device /dev/sgx_provision:/dev/sgx_provision```  
  ```--device /dev/sgx_enclave:/dev/sgx_enclave```

## Out-of-proc attestation support
This image supports out-of-proc attestation using Intel SGX. To allow this, the Intel SGX AESM Service will need to be made available by running the container with the following parameters:  
   ```--volume /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket```  
   ```--env SGX_AESM_ADDR=1```

## Versions

All Docker images offered are available in [this table](https://github.com/openenclave/openenclave/blob/master/DOCKER_IMAGES.md).

The base Docker images can be pulled from Dockerhub like so:
```docker pull oejenkinscidockerregistry.azurecr.io/openenclave-base-ubuntu-20.04:2022.06.0931```

Tags correspond to different Open Enclave or Intel SGX PSW/DCAP versions. You can use the `latest` tag to pull in the container with the latest component versions.
