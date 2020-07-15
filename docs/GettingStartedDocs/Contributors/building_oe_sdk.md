# Building the Open Enclave SDK

#### 1. Determine the SGX support level on your development/target system

The Open Enclave SDK runs on Linux systems, whether those systems are inside virtual machines or directly on top of the bare metal machines.
The Open Enclave feature set exposed on a system varies on the SGX support level requested and available.
Currently, the Open Enclave SDK implementation supports three different SGX support levels. This is explained in [next section](building_oe_sdk.md#2-understand-the-open-enclave-operation-modes).

The SDK setup process for each mode has minor differences. Since these differences are not fully compatible between modes, it is imperative for a user to know the SGX support level on their target system to ensure the correct SDK setup.

Please refer to the following [documentation](/docs/GettingStartedDocs/SGXSupportLevel.md) to determine the SGX support level for your target system.

#### 2. Understand the Open Enclave operation modes

  Open Enclave today supports the following three operation modes -

   - `SGX1`: This mode can handle all the generic SGX features.

   - `SGX1+FLC`: In this mode, the Open Enclave SDK takes advantage of the Flexible Launch
                 Control mode for better managing architectural enclaves.

   - `Simulation`: Open Enclave comes with an SGX software simulation mode that simulates a subset of
                  the SGX feature set. This simulator enables the Open Enclave SDK to run on
                  systems without actual SGX hardware support.

   Different Open Enclave operating modes require different SGX support levels.

   | Open Enclave operation mode|  SGX support level needed to run on |
   |:---------------------------|:-----------------------------------:|
   | SGX1+FLC                   | SGX1+FLC                            |
   | SGX1                       | SGX1 or SGX1+FLC                    |
   | Simulation                  | Any level                           |


   #### 3. Build, install and run

   Choose an operating mode that is compatible with the SGX support level of your target system.
   The links below contain instructions on how to set up Open Enclave SDK environment for a given mode.

On Ubuntu 1604 or Ubuntu 1804
  - [Set up Open Enclave SDK for SGX1+FLC](SGX1FLCGettingStarted.md)
  - [Set up Open Enclave SDK for SGX1](SGX1GettingStarted.md)
  - [Set up Open Enclave SDK for simulation mode](SimulatorGettingStarted.md)

On RHEL8
 - [Set up Open Enclave SDK on RHEL8](ExperimentalSupportRHEL8.md)

On Windows
 - [Set up Open Enclave SDK for SGX1+FLC](WindowsSGX1FLCGettingStarted.md)
 - [Set up Open Enclave SDK for SGX1](WindowsSGX1GettingStarted.md)
 - [Set up Open Enclave SDK for simulation mode](WindowsSimulatorGettingStarted.md)

## Samples

### On Linux
Assuming you install the SDK as below (also described in the [basic install section](LinuxInstallInfo.md#basic-install-on-linux))

```bash
cmake -DCMAKE_INSTALL_PREFIX=~/openenclave ..
make install
```

Open Enclave samples can be found in ~/openenclave/share/openenclave/samples

See [Open Enclave samples](/samples/README_Linux.md) for details.

### On Windows

Assuming you install the SDK as below (also described in the [basic install section](WindowsInstallInfo.md#basic-install-on-windows))

```bash
cmake .. -G  Ninja -DNUGET_PACKAGE_PATH=C:\oe_prereqs -DCMAKE_INSTALL_PREFIX:PATH=C:\openenclave"
ninja install
```
Open Enclave samples can be found in c:\openenclave\share\openenclave\samples

See [Open Enclave samples](/samples/README_Windows.md) for details.

## Using the Open Enclave SDK

Additional information such as the API Reference and supported libs can be found [here](/docs/GettingStartedDocs/APIs_and_Libs.md).
