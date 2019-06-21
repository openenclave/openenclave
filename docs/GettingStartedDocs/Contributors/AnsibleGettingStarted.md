# Getting started with Ansible

The Open Enclave repository contains various playbooks to configure the supported platforms for either developing Open Enclave applications or maintaining the SDK itself.

If you are interested in the Open Enclave deployment options via Ansible, see [this section](https://github.com/openenclave/openenclave/tree/master/scripts/ansible#open-enclave-deployment-options-via-ansible) from our Ansible README.

## Install the Ansible package

The Ansible package works reliably (as tested) only on Unix platforms due to the various unix specific internal code.

If you wish to run Ansible from a Windows machine, feel free to enable the [Windows Subsystem for Linux](https://docs.microsoft.com/en-us/windows/wsl/install-win10), install the Ubuntu (16.04 or 18.04) distribution from the Windows store, and open the Linux terminal.

To get Ansible ready to use, simply run the [install-ansible.sh](/scripts/ansible/install-ansible.sh) script (this requires execution with sudo).

After the script finishes, you can check that Ansible is installed by running:

```
ansible --version
```

Ansible communicates with the target machines via:

* SSH (port 22) if the target machine is a Linux system
* WinRM (port 5986) if the target machine is a Windows system

## Steps to configure target Ansible machines

1. Make sure that the target platform is included in the [supported operating systems](https://github.com/openenclave/openenclave/blob/master/scripts/ansible/README.md#supported-platforms-by-the-ansible-playbooks) by the Open Enclave playbook files.

2. Configure SSH / WinRM on the target machines:

    * SSH needs to be configured only on the target Linux machines. From the terminal where Ansible is used, make sure you can SSH into the Linux machines without any password prompt. You may need to generate a SSH key pair via `ssh-keygen` and authorize the key via `ssh-copy-id`.

    * WinRM needs to be configured only on the Windows machines. Make sure that WinRM is running and it allows remote auth via user and password. If you don't have WinRM configured on the Windows machines, execute the following [official Ansible PowerShell steps](https://docs.ansible.com/ansible/latest/user_guide/windows_setup.html#winrm-setup). After these steps are successfully executed, WinRM is properly configured.

3. Make sure that the Linux machines SSH (port 22) or Windows machines WinRM (port 5986) are reachable from the terminal where Ansible is used.

    Check the communication port for every target machine. You may need to open some extra firewall ports if the machines are running in a public cloud and you are using the public address.

4. Set up the Ansible inventory with connection details for all the target machines. See details on how to do this [here](/scripts/ansible/inventory).

5. Change directory to `scripts/ansible` and execute the following command:

    ```
    ansible -m setup all
    ```

    This will try and execute the `setup` Ansible built-in module and get platform details from every machine added to the [inventory](/scripts/ansible/inventory). If this command finishes without any error, the Ansible machines are prepared to run our playbooks from the [ansible](/scripts/ansible) directory.
