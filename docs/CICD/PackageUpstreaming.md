Open Enclave SDK Package Upstreaming
====================================

Note: These steps must be performed on a system that is connected to Microsoft corp-net.

1. Install the repoapi_client tool

```bash
sudo apt-key adv --keyserver tux-devrepo.corp.microsoft.com --recv-keys C5E3FD35A3A036D0
echo "deb [arch=amd64] http://tux-devrepo.corp.microsoft.com/repos/tux-dev/ trusty main" | sudo tee /etc/apt/sources.list.d/tux-dev.list
sudo apt-get update
sudo apt-get install azure-repoapi-client
```

2. Get the package that you wish to upstream to the Microsoft APT repo onto your filesystem.

3. Create a file named msft.json with these contents (the "repositoryId" is for the default Ubuntu 16.04 repo):

```json
{
  "server": "azure-apt-cat.cloudapp.net",
  "protocol": "https",
  "port": "443",
  "repositoryId": "582bd623ae062a5d0fec5b8c",
  "username": "INSERT_USERNAME_HERE",
  "password": "INSERT_PASSWORD_HERE"
}
```

Note: The username/password for the user/password can be found in the OE-Jenkins Azure Key Vault.

4. Run the command below to upload the package to the packages.microsoft.com APT repo. It may take a few minutes to fully propagate through the APT system.

```bash
repoapi_client -config ./msft.json -addfile ./PACKAGE_NAME_HERE.deb
```

References
---------------
These instructions are based on [this document](https://msazure.visualstudio.com/One/_wiki/wikis/One.wiki?wikiVersion=GBwikiMaster&pagePath=%2FLinux%20Repo%20Docs%2FRepo%20operations).

