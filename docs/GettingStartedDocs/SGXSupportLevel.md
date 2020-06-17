# Determine the SGX support level

## Is your system SGX capable and enabled?

The new Intel SGX instruction extension was introduced with 7th Generation Intel® Core™
processor platforms and Intel® Xeon® processor E3 v5 for data center servers in 2015.

First, determine which processor you have by using one of the following command to find the CPU information on your system:
    - On Linux: `cat /proc/cpuinfo | grep 'model name'`
    - On Windows: `msinfo32` (check the "Processor" value in the UI)

For a system to be considered to be SGX enabled, it must meet all the following three conditions:

- `SGX capable`: The CPU in the system must support the Intel SGX extension.

    You can follow [Intel's instructions](https://www.intel.com/content/www/us/en/support/articles/000028173/processors.html) to look up your specific processor and determine if it supports SGX.

- The system BIOS must support Intel SGX control.

    BIOS support is required for Intel SGX to provide the capability to enable and configure the Intel SGX feature in the system.
    The system owner must opt in to Intel SGX by enabling it via the BIOS. This requires a BIOS from the OEM that explicitly supports
    Intel SGX. The support provided by the BIOS can vary OEM to OEM and even across an OEM’s product lines.

    Given the SGX feature is relatively new, not all BIOS support the control of the SGX feature even
    if a system is built with a SGX capable Intel processor. You would need to boot into BIOS to see if your BIOS supports SGX
    control.

- `SGX enabled`: Intel SGX must be enabled in the BIOS.

    Currently, most of the SGX capable systems has the SGX disabled by default in the BIOS. This default setting might change but
    for now, you need to manually enable it if it's not already enabled.

For more information around enable Intel SGX, see:
- [Detecting and Enabling Intel® SGX](http://www.youtube.com/watch?v=bca5NcjoEdc)
- [Properly Detecting Intel® SGX]( https://software.intel.com/en-us/articles/properly-detecting-intel-software-guard-extensions-in-your-applications)

## oesgx utility tool

The oesgx tool is provided in the Open Enclave SDK to help determine whether your system is SGX capable, that is, the CPU supports SGX or not. **You still need to make sure SGX is enabled from the BIOS**.

The oesgx tool also detects the presence of the SGX's sub-feature, Flexible Launch Control (FLC), which is required for a fully featured build of the Open Enclave SDK.

You can build oesgx from the build subfolder:

```bash
~/openenclave/build$ make oesgx
[100%] Built target oesgx
~/openenclave/build$ ls  output/bin/oesgx
output/bin/oesgx
```
 You will get one of the following three types of output from running the oesgx tool:

|                                oesgx output | SGX support level |
|:--------------------------------------------|:------------------:|
| CPU supports SGX_FLC:Flexible Launch Control<br>CPU supports Software Guard Extensions:SGX1| SGX1+FLC          |
| CPU supports Software Guard Extensions:SGX1 | SGX1              |
| CPU does not support SGX                    |   None            |

For reference, the outputs from oesgx that lines up with the above table are:

```bash
$ ./oesgx
CPU supports SGX_LC:Flexible Launch Control
CPU supports Software Guard Extensions:SGX1
```

```bash
$ ./oesgx
CPU supports Software Guard Extensions:SGX1
```

```bash
$ ./oesgx
CPU does not support SGX
```

> If running on a VM hosted on Windows Hyper-V, be aware that even if the host
> machine has SGX correctly enabled, the oesgx tool running in a Gen 1 VM on
> that host will still report that the "CPU does not support SGX". This is because
> Hyper-V will only expose SGX to specifically configured Gen 2 VMs.
