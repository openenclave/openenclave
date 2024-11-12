# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

This directory contains the Ansible work used to automate all the required tasks for setting up new Open Enclave environments, and new Jenkins agents for the CI / CD system.

To quickly install / uninstall Ansible, the script `install-ansible.sh` / `remove-ansible.sh` can be used.

Supported Ansible version: 8.x

# Open Enclave Deployment Options via Ansible

On the target machine where Open Enclave is desired to be configured, you may setup the environment in one of the following ways:

1. Open Enclave environment for contributors:

    ```
    ansible-playbook oe-contributors-setup.yml
    ```

2. Open Enclave environment for contributors using ACC hardware:

    ```
    ansible-playbook oe-contributors-acc-setup.yml
    ```

3. Open Enclave vanilla environment (without SGX packages and with Azure-DCAP-Client package)

    ```
    ansible-playbook oe-vanilla-prelibsgx-setup.yml
    ```

4. Setup the remote Windows agents with all the requirements for the OE and DCAP Windows testing:

    ```
    ansible-playbook oe-windows-acc-setup.yml
    ```

    This assumes that the inventory was properly set up with the `windows-agents` machines.

# Supported platforms by the Ansible playbooks

* Ubuntu 20.04
* Windows Server 2022 (SGX-enabled)
