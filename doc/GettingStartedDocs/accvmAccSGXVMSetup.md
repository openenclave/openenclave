
#	How to setup a ACC SGX VM

The ACC team made available a set of Azure VMs (up to 10 cores in total) with SGX support for the users of "EOSG Dev and Test" (subscription e5839dfd-61f0-4b2f-b06f-de7fc47b5998) subscription to create openEnclave VM for development purpose.

Those ACC VMs have the following configurations: 

  - VMs were created off a Windows server host
  - Host hardware: Intel CoffeeLake processor, which has SGX-FLC SGX support level
  - VMs were configured to support SGX-FLX 
  - VM OS: a special Ubuntu 16.04 dev image

## Instructions on how to provision an ACC SGX VM:


###	Prerequisites 

   You may want to make sure you have access to the Azure "EOSG Dev and Test" subscription 
   
###	Required Tools and scripts 

  On your Windows host:
  
  - Install [Azure CLI 2.0](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)(at least 2.0.43)
  -	Download Powershell scripts from [here](/scripts/vmcreate/accvm) and copy them
    to your local directory, for example D:\tools\openenclave\CoffeelakeScripts\Scripts
 
###	Deploy and prepare the VM

-   Login to Azure portal by running the following Azure CLI command on your host

     az login

-   Set the default subscription for your account if it has multiple active subscriptions

    az account set --subscription "YourSubscriptionName"
    
    ps. "EOSG Dev and Test" is the subscription name used in this doc.
                
- 	Create a resource group, for example youralias-acc-rg in East US region

    az group create -l eastus -n youralias-acc-rg

      For example:
          PS D:\tools\openenclave\CoffeelakeScripts\Scripts> az group create -l eastus -n youralias-acc-rg
          {
            "id": "/subscriptions/e5839dfd-61f0-4b2f-b06f-de7fc47b5998/resourceGroups/youralias-acc-rg",
            "location": "eastus",
            "managedBy": null,
            "name": "youralias-acc-rg",
            "properties": {
              "provisioningState": "Succeeded"
            },
            "tags": null
          }


- 	Create a storage account in Azure (you’ll use this in part 2.a.i) in East US region

     az storage account create --resource-group youralias-acc-rg --location eastus --name yoursgxstorage --kind Storage --sku Standard_LRS

       For example:

        PS D:\tools\openenclave\CoffeelakeScripts\Scripts> az storage account create --resource-group youralias-acc-rg --location eastus --name yoursgxstorage --kind Storage --sku Standard_LRS
        {
          "accessTier": null,
          "creationTime": "2018-08-06T22:12:48.281663+00:00",
          "customDomain": null,
          ...
          ...
            "restrictions": null,
            "tier": "Standard"
          },
          "statusOfPrimary": "available",
          "statusOfSecondary": null,
          "tags": {},
          "type": "Microsoft.Storage/storageAccounts"
        }
        PS D:\tools\openenclave\CoffeelakeScripts\Scripts>
        

- 	Provision ACC VM by running the New-AccCreateDevVm.ps1 script 

    Open a Powershell command windows and run the following script from D:\tools\openenclave\CoffeelakeScripts\Scripts
    
    Attention: Before running the New-AccCreateDevVm.ps1 script below, you want to make sure your password meet the requirement called out in the note section below it.

        PS D:\tools\openenclave\CoffeelakeScripts\Scripts\.\New-AccCreateDevVm.ps1 -Subscription "EOSG Dev and Test" -ResourceGroupName youralias-acc-rg -StorageAccountName yoursgxstorage -VMName yourVMname -VmUserName youradminusername -VmPassword yourFakePasswordHere@0


         Note:
            You want to make sure the VmUserName and the VmPassword meet the following requirements before running New-AccCreateDevVm.ps1
            - Password must have the 3 of the following: 1 lower case character, 1 upper case character, 1 number and 1 special character and have length at least 12.
            - admin user name cannot contain upper case character A-Z, special characters \/"[]:|<>+=;,?*@#()! or start with $ or -
            - If the 10 cores limt was hit, you might encounter the following error message.
              Error Code: QuotaExceeded
              Message: Operation results in exceeding quota limits of Core. Maximum allowed: 10, Current in use: 10, 
              Additional requested:             
              Please read more about quota increase at http://aka.ms/corequotaincrease.
              [2018/08/06, 22:23:21:375]      ERROR   VM Creation failed.

           
     This will take about ** minutes to complete, you would have to wait for it to complete before you could go any further
    
     On a successful deployment, you will get messages like the following:
     
      For example:

        [2018/08/06, 22:34:09:657]      INFO    Log File: D:\tools\openenclave\CoffeelakeScripts\Scripts\New-AccCreateVmImageLog-2018.08.06.22.34.09.657.log
        [2018/08/06, 22:34:09:664]      INFO    Creating New ACC VM:
                                                Subscription: EOSG Dev and Test
                                                ResourceGroupName: youralias-acc-rg
                                                StorageAccountName: yoursgxstorage
                                                AccImage: acc-ubuntu-dev
                                                VmName: yourVMname
                                                VmUsername: youradminusername
                                                VmSize: Standard_DC2s
        [2018/08/06, 22:34:20:823]      INFO    Creating Linux Vm: yourVMname of VmSize: Standard_DC2s.
        [2018/08/06, 22:38:15:933]      INFO    VM Created: yourVMname, Public IP: 23.96.33.79
        PS D:\tools\openenclave\CoffeelakeScripts\Scripts>
 


- 	Connect to VM, set up your ssh private key linked to your github account so you can clone the private repository

      ssh into the newly created VM at Public IP from the last step: eg 23.96.33.79
    
        PS D:\tools\openenclave\CoffeelakeScripts\Scripts> ssh youradminusername@23.96.33.79
        youradminusername@23.96.33.79's password:
        Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.13.0-41-generic x86_64)

         * Documentation:  https://help.ubuntu.com
         * Management:     https://landscape.canonical.com
         * Support:        https://ubuntu.com/advantage

        ...
        youradminusername@yourVMname:~$

    
     Generate ssh key pair and add the public key to your github settings
    
        youradminusername@yourVMname:~$ ssh-keygen -t rsa -b 4096
        youradminusername@yourVMname:~$ cd .ssh
        youradminusername@yourVMname:~/.ssh$ ls
        authorized_keys  id_rsa  id_rsa.pub
        youradminusername@yourVMname:~/.ssh$ cat id_rsa.pub
        .....

     Add public key to your github account so you can clone the Open Enclave repro, which is a private repo
     

- 	Clone the Open Enclave repo

      For example:
        
          youradminusername@yourVMname:~$ git clone git@github.com:Microsoft/openenclave.git
          Cloning into 'openenclave'...
          The authenticity of host 'github.com (192.30.253.113)' can't be established.
          RSA key fingerprint is SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8.
          Are you sure you want to continue connecting (yes/no)? yes
          Warning: Permanently added 'github.com,192.30.253.113' (RSA) to the list of known hosts.
          remote: Counting objects: 38998, done.
          remote: Compressing objects: 100% (107/107), done.
          remote: Total 38998 (delta 104), reused 109 (delta 71), pack-reused 38820
          Receiving objects: 100% (38998/38998), 27.50 MiB | 42.80 MiB/s, done.
          Resolving deltas: 100% (21636/21636), done.
          Checking connectivity... done.
          Checking out files: 100% (11857/11857), done.

- 	Download these Intel SGX packages from a system that has access to corpnet (your Windows dev box for example):
    - http://10.224.140.70:8888/libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
    - http://10.224.140.70:8888/libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
    - http://10.224.140.70:8888/libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
    - http://10.224.140.70:8888/libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
    - http://10.224.140.70:8888/sgx_linux_x64_driver.bin
    - http://10.224.140.70:8888/azquotprov_0.2-1_amd64.deb
                
         For example:
         
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb -out libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb -out libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb -out libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb -out libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/sgx_linux_x64_driver.bin -out sgx_linux_x64_driver.bin
              PS D:\tools\openenclave> wget http://10.224.140.70:8888/azquotprov_0.2-1_amd64.deb -out azquotprov_0.2-1_amd64.deb
              PS D:\tools\openenclave> dir
              Directory: D:\tools\openenclave
                Mode                LastWriteTime         Length Name
                ----                -------------         ------ ----
                -a----         8/6/2018   3:58 PM          21912 libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
                -a----         8/6/2018   3:58 PM          60628 libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
                -a----         8/6/2018   3:59 PM          23752 libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
                -a----         8/6/2018   3:58 PM         240038 libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
                -a----         8/6/2018   3:59 PM          60505 sgx_linux_x64_driver.bin
                -a----         8/16/2018  3:59 PM         41580 zquotprov_0.2-1_amd64.deb

 
- Copy above six package files onto your ACC VM and put them in a directory. Note that the above filenames are subject to change when new versions come out. Go to http://10.224.140.70:8888/ if you want a list of all possible packages available, only those packages 
listed above are really needed.

   For example:

      On Windows host

      PS D:\tools\openenclave> scp libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb youradminusername@23.96.33.79:/home/youradminusername
      PS D:\tools\openenclave> scp libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb youradminusername@23.96.33.79:/home/youradminusername
      PS D:\tools\openenclave> scp libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb youradminusername@23.96.33.79:/home/youradminusername
      PS D:\tools\openenclave> scp libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb youradminusername@23.96.33.79:/home/youradminusername
      PS D:\tools\openenclave> scp sgx_linux_x64_driver.bin youradminusername@23.96.33.79:/home/youradminusername
      PS D:\tools\openenclave> scp azquotprov_0.2-1_amd64.deb youradminusername@23.96.33.79:/home/youradminusername      


      What you will see on the VM after above copying

      youradminusername@yourVMname:~$ ls -l
      total 408
      -rw-rw-r--  1 youradminusername youradminusername  60628 Aug  6 18:25 libsgx-enclave-common_1.0.101.45575-1.0_amd64.deb
      -rw-rw-r--  1 youradminusername youradminusername  21912 Aug  6 18:24 libsgx-enclave-common-dev_1.0.101.45575-1.0_amd64.deb
      -rw-rw-r--  1 youradminusername youradminusername 240038 Aug  6 18:26 libsgx-ngsa-ql_1.0.101.45575-1.0_amd64.deb
      -rw-rw-r--  1 youradminusername youradminusername  23752 Aug  6 18:25 libsgx-ngsa-ql-dev_1.0.101.45575-1.0_amd64.deb
      drwxrwxr-x 20 youradminusername youradminusername   4096 Aug  6 17:56 openenclave
      -rw-rw-r--  1 youradminusername youradminusername  60505 Aug  6 18:27 sgx_linux_x64_driver.bin
      -rw-rw-r--  1 youradminusername youradminusername  41580 Aug 16 00:58 azquotprov_0.2-1_amd64.deb
      youradminusername@yourVMname:~$

- Install Azure quote provider package (azquotprov_0.2-1_amd64.deb), which is one of above  for attestation validation purpose
   (with installing this package, you will see two attestation related unitest failures)

       For example:
        youradminusername@yourVMname:~$sudo dpkg -i azquotprov_0.2-1_amd64.deb


 ### Install Intel SGX FLC support software packages

 There are two packages needed here because the ACC SGX VM has SGX+FLC support.
 
- Intel(R) SGX driver with FLC support
- Intel(R) NGSA SDK

To install these prerequisites type the following commands from the root of
the source distribution.

```
  sudo ./scripts/install-prereqs
  sudo make -C prereqs USE_LIBSGX=1 USE_PKGS_IN=/home/youradminusername
  sudo make -C prereqs install USE_LIBSGX=1 USE_PKGS_IN=/home/youradminusername
```
   For example:
   
      youradminusername@yourVMname:~/openenclave$ sudo ./scripts/install-prereqs
      youradminusername@yourVMname:~/openenclave$ sudo make -C prereqs USE_LIBSGX=1 USE_PKGS_IN=/home/youradminusername
      youradminusername@yourVMname:~/openenclave$ sudo make -C prereqs install USE_LIBSGX=1 USE_PKGS_IN=/home/youradminusername
 

### Build

   You can go straight to the SGX+FLC's [build](SGX1FLCGettingStarted.md#build) section to continue the SDK setup process
 
 
