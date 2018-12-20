# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

Add Jenkins slave
=========

This role will install needed Jenkins students (slaves) for both linux and windows. That includes all the needed requirements for openenclave.

Requirements
------------

All the python requirements are in the requirements.txt and can be installed with:

```
pip3 install -r requierements.txt
```

Ansible >=2.7

Ubuntu 16.04 targets (should work with 18.04 also, but not tested)

Create the node on Jenkins master

Add the external role:

```
ansible-galaxy install kobanyan.jenkins-jnlp-slave

```

Add the IPADDRESS in the hosts file from the repository.

Role Variables
--------------

The bellow variables need to be changed in var/variables.var for the playbook to execute succesfully

jenkins_master: "JENKINS_MASTER_URL"
jenkins_slave_secret: "SECRET" #The secret must be taken from when the node is created


Dependencies
------------

https://galaxy.ansible.com/kobanyan/jenkins-jnlp-slave 

Example running
----------------
```
ansible-playbook -i hosts deploy_jenkins.yml -u **USER**
```
