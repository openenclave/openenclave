# host variables

This place is the most useful when using different Windows nodes with
different passwords. For example 2 Windows Server nodes can have the
same username and different passwords.

Just create a file for the nodes that have different password from the
one present in group_vars. Example for "node5":
```
ansible_user: Administrator
ansible_password: different_password
```

When setting up new Jenkins slaves, this place is the best to set
individual configurations, such as:

```
jenkins_agent_name: "new-jenkins-agent"
jenkins_agent_executors_count: 2
jenkins_agent_label: "hardware"
jenkins_agent_root_dir: "/home/jenkins"
```

The Windows CI/CD testing takes place for both Open Enclave and DCAP libraries.

Since the SGX Windows machines configuration is slightly different for these
two scenarios, one must use the following variable to differentiate the
targeted Ansible Windows nodes when configuring them:

```
launch_configuration: "SGX1"
```
