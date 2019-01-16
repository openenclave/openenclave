Sample: Echo Socket Enclave through Azure IoT Edge
=============

We will showcase the end-to-end Secure Enclave promise. You will need to set up a Grapeboard device using the [Grapeboard setup](grapeboard.md) instructions.

This sample builds on the [sockets sample](sample_sockets.md).

# SGX Sample Server

You can run a simulation of a cloud service on Windows SGX, or in simulation. See [building with Windows and SGX](win_sgx_dev.md) for details.

You will need to add a firewall exception for port 12345 in order to be able to connect to the SampleServerApp from another machine as instructed at the end of this section. When Windows prompts you about the exception, select Yes. If you do not get the prompt, you can run the following command to add the exception:
   ```
   netsh advfirewall firewall add rule name=`"SampleServerApp 12345`" protocol=TCP dir=in localport=12345 profile=any action=allow
   ```
   We will use the SampleServerApp. The path below assumes SGX simulation:
   ```
   openenclave\new_platforms\build\x86-SGX-Simulation-Debug\out\bin\Debug> SampleServerApp.exe
   Listening on 12345...
   ```

That's it for the server. 

# ARM TrustZone Edge Module

 We will use a Grapeboard device (a TrustZone capable device) to connect to our secure cloud service.

1. [Set up an Azure Container Repository](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-get-started-portal).
2. Set up passwordless login to the Grapeboard device:
   * On a x64 Linux host run the following, unless already done in the past:
      ```
      ssh-keygen
      ```
   * On the x64 Linux host run the following, replacing the placeholder with the actual IP address of the Grapeboard device:
      ```
      ssh-copy-id root@<ip-address-of-grapeboard>
      ```
3. On the x64 Linux host, build ``new_platforms`` using ``build_optee.sh``. Please follow the [Linux build instructions](linux_arm_dev.md).
4. On the x64 Linux host run the following to create docker image for SampleClientApp and push it into your Azure Container Repository (replace placeholders with the arguments first):
    ```
    cd new_platforms/scripts/build/aarch64/out/bin
    ./../../../../build_container.sh <user@ip-address-of-grapeboard> <container-repository> <container-repository-username> <container-repository-password>
    ```
5. To prevent container connectivity issues, run the following steps on the Grapeboard (and replace the hostname placeholder):
    ```
    HOSTNAME=<new-hostname-for-grapeboard>
    echo $HOSTNAME > /etc/hostname
    hostname $HOSTNAME
    ```
6. On the Grapeboard device, start ``tee-supplicant`` in order in order for TAs to be able to run:
    ```
    tee-supplicant &
    ```
7. Deploy IoT Edge onto the Grapeboard device. You can skip the Docker deployment step, your image already comes with Docker.
    1. Download and install Security Manager:
        ```
        wget https://aka.ms/iot-edge-aarch64
        unzip iot-edge-aarch64
        apt-get install ./libiothsm-std_1.0.5~dev18569510-1_arm64.deb
        apt-get install ./iotedge_1.0.5\~dev-1_arm64.deb
        ```
    2. [Create IoT Hub](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-create-through-portal)
    3. [Create IoT Edge Device](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-register-device-portal)
    4. Using Portal, change ``Configure advanced Edge Runtime settings`` and set Edge Hub image name ``mcr.microsoft.com/azureiotedge-hub:1.0.4-linux-arm32v7`` and Edge Agent image name ``mcr.microsoft.com/azureiotedge-agent:1.0.4-linux-arm32v7``
    5. Update IoT Edge Runtime configurations: ``vi /etc/iotedge/config.yaml``
        * Set ``provisioning`` -> ``device_connection_string`` with the device connection string retrieved in the last step
        * Set ``agent`` -> ``config`` -> ``image`` with ``mcr.microsoft.com/azureiotedge-agent:1.0.4-linux-arm32v7``
    6. Restart the IoT Edge runtime: ``systemctl restart iotedge`` 
    7. Wait until ``docker ps`` shows both ``edgeHub`` and ``edgeAgent`` running
    8. To validate against the secure cloud service, [add the following module into the deployment](https://docs.microsoft.com/en-us/azure/iot-edge/how-to-deploy-modules-portal). Update the ``<sgx-host>`` placeholder with the IP address of the host where you started SampleServerApp. 
    1. If you go through Portal, use ``sampleClient`` as a Name, ``<container-repositor>/sampleclient:latest`` as an Image URI and the following snippet as the Container Create Options:
        ```
        {
          "Env": ["HOST=<sgx-host>", "PORT=12345"],
          "HostConfig": {
            "Binds": ["/lib/optee_armtz:/lib/optee_armtz"],
            "Devices":[{"PathOnHost":"/dev/tee0","PathInContainer":"/dev/tee0","CgroupPermissions":"rwm"}]
          }
        }
        ```
        You will also need to specify your Azure Container Registry credentials in the Container Registry Settings.
    
    1. If you use deployment.json for the deployment, the snippet you need to use is this:
        ```
        "sampleClient": {
          "version": "1.0",
          "type": "docker",
          "status": "running",
          "restartPolicy": "always",
          "settings": {
            "image": "<container-repositor>/sampleclient:latest",
            "createOptions": "{\"Env\":[\"HOST=<sgx-host>\",\"PORT=12345\"],\"HostConfig\":{\"Binds\":[\"/lib/optee_armtz:/lib/optee_armtz\"],\"Devices\":[{\"PathOnHost\":\"/dev/tee0\",\"PathInContainer\":\"/dev/tee0\",\"CgroupPermissions\":\"rwm\"}]}}"
          }
        }
        ```
        You will also need to specify your Azure Container Registry credentials using the following snippet:
        ```
            "registryCredentials": {
              "mytest": {
                "username": "<container-repository-username>",
                "password": "<container-repository-password>",
                "address": "<container-repository>"
              }
            }

        ```
9. The OP-TEE console output (via serial line connection to the Grapeboard) should show the following repeating:

```
Connecting to <sgx-host> 12345...
Sending message: Hello, world!
Received reply: Hello, world!
```

Behind the scenes, the Azure IoT Edge module is running the SampleClientApp, which executes a TA (Client TA).
That TA connects to the TA hosted by the SecureServerApp (Server TA).
The Client TA sends ``Hello, world!`` to the Server TA, which echoes it back. 
