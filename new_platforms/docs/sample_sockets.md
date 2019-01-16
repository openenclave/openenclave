Sample: Echo Sockets
=============

This sample demonstrates how two enclaves can communicate with each other over a standard socket connection.

If you want to jump right in, see [Building the Sample](sample_sockets.md#building-the-sample).

# Overview

This sample builds three components:

* REE: Server host app
* REE: Client host app
* TEE: Sample TA

The same Sample TA includes both client and server code, and hence is used by both the client and server host apps.
The EDL file declares two ECALLs (i.e., Enclave calls):

```
trusted {
        /* define ECALLs here. */
        public int ecall_RunClient([in, string] char* server, [in, string] char* port);
        public int ecall_RunServer([in, string] char* port);
    };
```

In addition, the EDL includes `socket.edl` provided by the Open Enclave SDK which defines standard socket APIs as OCALLs (i.e., "outcalls" to the untrusted host app).
This allows the enclave to use standard socket APIs as though it were a regular program even though it runs in a TEE.
In turn, this allows a developer to take an existing networked REE application and turn it into a TA without needing to re-implement communication.
Note that the actual socket is opened by the host app, but any encrypted data sent from and received into the enclave is not be readable by the host app.

```
+--------------+                    +----------+
|REE:          |  ECALL:RunServer   |TEE:      |
| SampleServer | +----------------> | SampleTA |
|              |  OCALL:Listen      |          |
|              | <----------------+ |          |
+--+---+-------+                    +----------+
   ^   |
   |   |
   |   | Standard Sockets
   |   |
   |   v
+--+---+-------+                    +----------+
|REE:          |  ECALL:RunClient   |TEE:      |
| SampleClient | +----------------> | SampleTA |
|              |  OCALL:Connect     |          |
|              | <----------------+ |          |
+--------------+                    +----------+
```

```
    /* Create connection. */
    s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (s == INVALID_SOCKET) {
        goto Done;
    }
    if (connect(s, ai->ai_addr, ai->ai_addrlen) == SOCKET_ERROR) {
        goto Done;
    }
```

**Note**: The same enclave code runs on both SGX and OP-TEE without modification.

# Building the Sample

To demonstrate the versatility of this sample it is assumed that you build the Sample Client for the Grapeboard and the Sample Server for SGX.
The idea is to simulate a scenario where there is a small edge-class device communicating with a large server-class device, 
with the endpoints of the socket connection being protected by TEE's.

## ARM TrustZone (Grapeboard)

Requirements: A Grapeboard and a Linux development environment.
Get started with the Grapeboard [here](grapeboard.md).

1) Build the Open Enclave SDK, along with samples, according to the [Linux Development](linux_arm_dev.md#building-the-sdk) guide.
2) Copy the following from your development machine to the Grapeboard:
    ```
    scp scripts/build/aarch64/out/bin/sampleclientapp root@<ip>:
    scp scripts/build/aarch64/out/bin/sampleserverapp root@<ip>:
    scp scripts/build/aarch64/out/bin/aac3129e-c244-4e09-9e61-d4efcf31bca3.ta root@<ip>:/lib/optee_armtz
    ```
3) On the target, start the TEE supplicant.
    ```
    tee-supplicant &
    ```
 You are now ready to start the host app.
 See [run your code](sample_sockets.md#running-the-sample) or start a Server App on SGX in the following section.
 
 *Note*: There is currently a known issue when running the Server and Client cannot run on the same board simultaneously.
 
## Intel SGX

Requirements: A Windows development environment and an SGX-capable Windows machine.

1) Build the solution, configuration `Debug\x86` according to the [Windows Development](win_sgx_dev.md) guide.
2) After a successful build, copy the following bits to your SGX-capable machine:
   ```
   openenclave\new_platforms\build\x86-SGX-Debug\out\bin\Debug\socketclient_host.exe
   openenclave\new_platforms\build\x86-SGX-Debug\out\bin\Debug\socketserver_host.exe
   openenclave\new_platforms\build\x86-SGX-Debug\out\bin\Debug\sockets_enclave.signed.dll
   ```

Either continue building a simulation sample at the next step, or jump down to [run your code](sample_sockets.md#running-the-sample).

## Simulation

Requirements: A Windows development environment.

For this sample, you build an SGX simulated Server, and an OP-TEE simulated Client.

1) Build the solution, configuration `DebugSimulation\x86` according to the [Windows Development](win_sgx_dev.md) guide.
2) After a successful build, copy the `SGX Simulation` bits to your working Server directory:
   ```
   openenclave\new_platforms\build\x86-SGX-Simulation-Debug\out\bin\Debug\socketclient_host.exe
   openenclave\new_platforms\build\x86-SGX-Simulation-Debug\out\bin\Debug\socketserver_host.exe
   openenclave\new_platforms\build\x86-SGX-Simulation-Debug\out\bin\Debug\sockets_enclave.signed.dll
   ```
3) Build the solution, configuration `DebugOpteeSimulation\x86`.
4) Copy the `OP-TEE Simulation` bits to your working Client directory:
   ```
   openenclave\new_platforms\build\x86-ARMTZ-Simulation-Debug\out\bin\Debug\socketclient_host.exe
   openenclave\new_platforms\build\x86-ARMTZ-Simulation-Debug\out\bin\Debug\socketserver_host.exe
   openenclave\new_platforms\build\x86-ARMTZ-Simulation-Debug\out\bin\Debug\aac3129e-c244-4e09-9e61-d4efcf31bca3.dll
   ```
Note that for OP-TEE the Sample TA is a UUID.
This is an artifact of how OP-TEE interacts with and loads TA's.

# Running The Sample

Regardless of which platforms you decided to build, the sample is executed the same way.

1. If the server and client run on different machines, ensure that the corresponding port is open in the firewall for testing.
For example, on Windows, using the default port, do:
    ```
    netsh advfirewall firewall add rule name=`"SampleServerApp 12345`" protocol=TCP dir=in localport=12345 profile=any action=allow
    ```
2. Start the server from the command line:
    ```
    >SampleServerApp
    Listening on 12345...
    ```
3. Start the client from the command line: 
   If the Server is remote, pass in the IP and Port on the command line (localhost:12345 is default)
    ```
    > SampleClientApp 10.10.10.1 12345
    Connecting to localhost 12345...
    Sending message: Hello, world!
    Received reply: Hello, world!
    ``` 

When both applications run, a text message is sent from one enclave to the other, which echoes it back. 
Both host apps start their Sample TA with an ECALL to indicate to the enclave to either run the client or server code.
The enclaves then request a socket using standard socket APIs from the host app via OCALLs.
They then use this socket to communicate with each other using the host apps as proxies.

If the enclaves add a layer of encryption atop the data being sent over the socket,
for instance via TLS (not shown in the sample), the host apps cannot snoop or modify the data.

## Debugging With Simulation

You can also run these samples under a debugger in Visual Studio.

* Set the SampleClientApp or SampleServerApp (your debug target) as the 'StartUp Project' in Visual Studio.
* SGX Simulation:
    * Build `DebugSimulation/x86`
    * Start the debugger using `Intel(R) SGX Debugger`
    * Note: Running both as simulated SGX applications under the Intel Debugger on the same machine at the same time has been known to cause issues.
* OP-TEE Simulation:
    * Build `DebugOpteeSimulation/x86`
    * Start the debugger using `Local Windows Debugger`

# Next Steps

Use the samples built here in an IoT Edge deployment. Get started [here](sample_edge_sockets.md).
