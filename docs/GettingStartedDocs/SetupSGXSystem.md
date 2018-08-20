# How to enable SGX on a system and create a Linux VM to run on a Windows host

## Enable SGX feature on your developer machine: 

- Your device needs to be running a Skylake (7th gen) or better Intel core i5/7 chipset 

- Even if your device has such a chipset, SGX may not be supported by the BIOS 
  - Most notably, Surface Book and Surface Pro do not support SGX 

- From the host BIOS, check that SGX is set to Enabled and not Software Controlled (Windows does not support OS enablement of SGX) 
  - On HP-Z240 workstations, this is under the Security settings 
  - Also check that your PRMRR is set to the maximum (128MB for Skylake/Kabylake devices) 
  - If the device is based on Coffeelake (not in general availability yet), also check that Flexible Launch Control (FLC) is not Disabled. 

## How to set up a Hyper-V SGX-enabled Ubuntu VM on your local developer machine: 

- Ensure that your host OS is on Windows 10 Fall Creators Update or better (1709) to support SGX in a VM: 
  - On the command line, run Winver 
  - Check that the version is 1709 or higher, if not, go to Windows Update when connected to corp domain and check for OS upgrades. 
- Enable Hyper-V feature in the host: https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v  

- The VM must be generation 2 and v8.1; you cannot create such a VM from the GUI, you must use powershell to create it.  
  - Copy the [New-SgxVM.ps1](/scripts/vmcreate/New-SgxVM.ps1) Powershell scripts from your local directory to create and configure a VM for SGX:  
       
  - Use New-SgxVM.ps1 to create your VM (needs to be run from administrator elevated powershell)  
    - You must provide a VMName and may optionally provide a VMPath as well.  
      - By default, the script allocates a max of 92MB of EPC memory to the VM  
      - You can change this with the Set-SgxVM.ps1 script later, or turn off SGX for the image entirely 
      - If the VM does not start using this default limit, then try setting it in decreasing 2MB increments until it does (the range varies from about 90-94MB for some reason)  
      - Note that at these high values, you can’t run an enclave on the host at the same time as the VM is running (no enclaves need to be running in the VM, the EPC is already reserved for it)  

- Get an Unbuntu image:  
  - Download a Ubuntu 16.04 LTS 64-bit ISO from: https://www.ubuntu.com/download/desktop/contribute?version=16.04.4&architecture=amd64  
  - From Hyper-V Manager, boot the ISO in the VM created by New-SgxVM.ps1  
    - right-click on your VM and select Settings… 
    - Under Memory, allocate fixed RAM for your VM to use (e.g. 8192MB)  
      - Do NOT enable Dynamic Memory, this has been known to cause hangs 
    - Under Security, disable Secure Boot 
    - Under SCSI Controller, Add a DVD Drive and point it to the ubuntu ISO 
    - Under SCSI Controller, Add a Hard Drive and new, dynamically expanding, blank VHDX. (127GB default size is fine it would reserve that space up front) 
    - Under Network, connect it to the Virtual Switch for your external network  
      - If no virtual switches exist, you can create a new one from the main Hyper-V interface Actions pane under Virtual Switch Manager… >  New virtual network switch 
      - Create an External virtual switch connected to the external network 
      - Go back to your VM settings and add the virtual switch 
     - Apply all the changes 

     - Under Firmware, order the boot devices to use DVD drive, Hard Drive then network 
     - Boot the VM  
       - It should boot into the Ubuntu DVD 
       - Install Ubuntu to the blank VHDX 

  
