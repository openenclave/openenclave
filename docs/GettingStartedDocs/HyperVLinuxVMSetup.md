# Setting up a Linux Hyper-V VM on Windows with SGX Support

_Note: Hyper-V support for SGX is not yet fully supported, but can be used as a "Preview" with the limitations
mentioned below._

To set up a Linux VM on your Windows machine, do the following:

1. Download an ISO for Ubuntu [18.04](http://releases.ubuntu.com/18.04/) or [16.04](http://releases.ubuntu.com/16.04/).
   A "Server install image" is sufficient.
1. Create a VM as follows.  Open "Hyper-V Manager", and do Action -> New -> Virtual Machine....
   - On the Specify Generation screen, choose Generation 2.
   - On the Configure Networking screen, choose Default Switch to ensure you can connect to it with a debugger.
   - On the Installation Options screen, choose the ISO file you downloaded.
   - All other options can be either left as the defaults or changed as desired.
1. Disable Secure Boot as follows.  In Hyper-V Manager, right click on the VM you created while it is stopped,
  and select Settings... -> Security and uncheck Enable Secure Boot.
1. Uncheck "Enable checkpoints" under the VM's Settings -> Checkpoints, since SGX will not work with checkpoints.
1. If using an SGX-capable machine, enable SGX for the VM as follows (this cannot be done from Hyper-V Manager):
   - Download [VirtualMachineSgxSettings.psm1](https://raw.githubusercontent.com/openenclave/openenclave/scripts/VirtualMachineSgxSettings.psm1)
   - Open an elevated PowerShell window (e.g., type "powershell" and click Run as Administrator)
   - Invoke the following commands, using the path to where you downloaded the file, and replacing MyVM with your VM name:
   ```
   Set-ExecutionPolicy Bypass -Scope Process
   Import-Module Drive:\Path\to\VirtualMachineSgxSettings.psm1
   Set-VMSgx -VmName MyVM -SgxEnabled $True -SgxSize 32
   ```
1. Start the VM and connect to it (right click, Connect...), finish the initial setup, reboot, and login.
   - Enable OpenSSH server installation when given the choice during setup.
   - All other options are sufficient to leave as the defaults or changed as desired.
