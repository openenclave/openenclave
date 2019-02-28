# Ansible inventory

Make sure to update the [hosts](/scripts/ansible/inventory/hosts) file with the targeted node addresses.

The hosts targeted by Ansible are grouped into:

* `linux-agents` - represent any Linux (Ubuntu 16.04 and Ubuntu 18.04) to be configured
* `windows-agents` - represent any Windows Server 2016 ACC machine to be configured

Ensure that [group_vars](/scripts/ansible/inventory/group_vars) contain the right details to connect to the targeted servers. There are 3 files with global variables applied to the machines:

* `all` - global variables applied to every Ansible targeted machine
* `linux-agents` - global variables applied only to the Linux machines declared in the [hosts](/scripts/ansible/inventory/hosts) file
* `windows-agents` - global variables applied only to the Windows Server 2016 ACC machines declared in the [hosts](/scripts/ansible/inventory/hosts) file

If you want to granularly apply configs only to a single Ansible target machine, you need to create a new file under [host_vars](/scripts/ansible/inventory/host_vars) directory. The file name must be the machine address as declared in the [hosts](/scripts/ansible/inventory/hosts) file. For more information on this, see the README from the [host_vars](/scripts/ansible/inventory/host_vars) directory.
