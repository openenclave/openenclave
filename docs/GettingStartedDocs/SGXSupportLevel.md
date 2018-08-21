
# Determine the SGX support level


Is your system SGX capable and enabled?
======================================

The new Intel SGX instruction extension was introduced with 7th Generation Intel® Core™ 
processor platforms and Intel® Xeon® processor E3 v5 for data center servers in 2015.

For a system to be considered to be SGX enabled, it must meet all the following three conditions:

- `SGX capable`: the CPU in the system must support the Intel SGX extension

    A list of Intel processors with the GX extension support could be found [here](https://ark.intel.com/Search/FeatureFilter?productType=processors&SoftwareGuardExtensions=true)

    Your CPU must be one of the processors in above list or its variants.You can use the following command to find the CPU information on your system
    - [Linux]    $ cat /proc/cpuinfo
    - [Windows]  Run msinfo32  (check the "Processor" item's value in the UI)
  
- The system BIOS must support Intel SGX control

    BIOS support is required for Intel SGX to provide the capability to enable and configure the Intel SGX feature in the system.
    The system owner must opt in to Intel SGX by enabling it via the BIOS. This requires a BIOS from the OEM that explicitly supports       Intel SGX. The support provided by the BIOS can vary OEM to OEM and even across an OEM’s product lines. 
    
    Given the SGX feature is relatively new, not all systems' BIOS support the control of the SGX feature even 
    if the system is built with a SGX capable Intel processor. You would need to boot into BIOS to see if your BIOS supports SGX             control.
    
- `SGX enabled`: Intel SGX must be enabled in the BIOS

    Currently, most of the SGX capable systems has the SGX disabled by default in the BIOS. This default setting might change but
    for now, you need to manually enable it if it's not enabled already.

Note: Optional Intel SGX enabling background information:
  - [Detecting and Enabling Intel® SGX](http://www.youtube.com/watch?v=bca5NcjoEdc)
  - [Properly Detecting Intel SGX]( https://software.intel.com/en-us/articles/properly-detecting-intel-software-guard-extensions-in-your-applications)
  
oesgx utility tool:
=======================================
 
 The oesgx tool is provided in the Openenclave SDK to help determine whether your system is SGX capable, that is, the CPU supports SGX or not. `"* You still need to make sure SGX is enabled from the BIOS *"`.
The oesgx tool also detects the presence of the SGX's subfeature, Flexible Launch Control, which impacts how to build and setup Open Enclave SDK.

   A prebuilt oesgx binary for Linux could be downloaded from [here](https://github.com/soccerGB/Openenclavedoc/tree/master/tools)
   
           You can also build this binary from the Open Enclave source tree
            ~/openenclave/build$ make oesgx
            [100%] Built target oesgx
            ~/openenclave/build$ ls  output/bin/oesgx
            output/bin/oesgx
 
 You will get one of the following three types of output from running the oesgx tool
  
 
|                                oesgx output | SGX support level |
|:--------------------------------------------|:------------------:|
| CPU supports SGX_FLC:Flexible Launch Control<br>CPU supports Software Guard Extensions:SGX1| SGX1+FLC          |
| CPU supports Software Guard Extensions:SGX1 | SGX1              |
| CPU does not support SGX                    |   None            |

    For example: Output from running the oesgx tool on three systems with different SGX support level
 
         $ ./oesgx
        CPU supports SGX_LC:Flexible Launch Control
        CPU supports Software Guard Extensions:SGX1

        $ ./oesgx
        CPU supports Software Guard Extensions:SGX1
        This is what we called "SGX 1" mode in this Open Enclave SDK context

        $ ./oesgx
        CPU does not support SGX

Note: If the oesgx tool is run a Windows Hyper-V Gen 1 Linux VM, it will report "CPU does not support SGX" 
      even the system is SGX capable and correctly enabled. Creating a Gen 2 VM is needed.

How to configure your dev machine to be SGX enabled
---------------------------------------------------

This section is for the Microsoft internal development purpose and will be removed before public reivew

- How to enable SGX on a system and create a Linux VM to run on a Windows host [here](SetupSGXSystem.md)

- How to provision an ACC Azure SGX Azure VM and setup Open Enclave SGX dev environment [here](accvmAccSGXVMSetup.md)
