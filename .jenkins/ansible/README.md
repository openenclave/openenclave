CI Students
=========

This role will install needed Jenkins students (slaves) for both linux and windows. That includes all the needed requirements for openenclave.

Requirements
------------

All the python requierements are in the requierements.txt and can be installed with:

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

Role Variables
--------------

#

Dependencies
------------

https://galaxy.ansible.com/kobanyan/jenkins-jnlp-slave 

Example running
----------------
```
ansible-playbook -i hosts deploy_jenkins.yml -u **USER**
```