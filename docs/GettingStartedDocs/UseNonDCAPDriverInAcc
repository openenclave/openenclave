#Using the Non-DCAP Driver in an ACC VM

ACC VMs come pre equipeed with the azure DCAP stack preinstalled. This can interfere with non-azure dcap clients, 
so in this case we must disable the dcap driver.

To do so, first lets get the non-dcap driver (if we haven't already).
```
curl https://download.01.org/intel-sgx/sgx-linux/2.9/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_95eaa6f.bin --output sgx_linux_x64_driver_2.6.0_95eaa6f.bin
```
And remove the dcap driver, or else the non-dcap driver, named 'isgx' will not start.
```
sudo modprobe -r intel_sgx
```
This will temporarily remove the dcap driver, named "intel_sgx" from the kernel. 
We will need more steps later to make this permanent.

Now we can install the intel non-dcap driver.
```
sudo chmod a+x sgx_linux_x64_driver_2.6.0_95eaa6f.bin
sudo ./sgx_linux_x64_driver_2.6.0_95eaa6f.bin
sudo modprobe -i isgx
```
Now if we look at /dev, the device /dev/sgx will be gone and /dev/isgx in its place.

But if we reboot the situation will be reverted.
To make it permanent, we need to edit a couple of config files, on in /etc/modules.d/ and one in /etc/modprobe.d.

First, /etc/modules-load.d/modules.conf will probably look like:
```
# /etc/modules: kernel modules to load at boot time.
#
# This file contains the names of kernel modules that should be loaded
# at boot time, one per line. Lines beginning with "#" are ignored.

intel_sgx
isgx
```

comment out intel_sgx, so the lines look like
```
#intel_sgx
isgx
```

This will prevent the kernel from loading the module, but in addition you want to ensure it is not loaded. 
intel_sgx will preempt isgx and prevent it from loading. So we need to blacklist it.

To do this, we add a conf file to /etc/modprobe.d. 
As superuser, create the file '/etc/modprobe.d/blacklist-intel-sgx.conf' with the contents:
```
blacklist-intel-sgx.conf
```
You can now reboot and the intel dcap sgx driver will no longer be loaded.
