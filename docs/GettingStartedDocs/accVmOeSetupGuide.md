
#	How to provision an ACC SGX VM and setup Open Enclave dev environment

The ACC team made available a set of Azure VMs for users to create SGX capable VMs for development purpose.

Those ACC VMs have the following configuration: 

  - VMs were created off a Windows server host
  - Host hardware: Intel CoffeeLake processor, which has SGX-FLC SGX support level
  - VMs were configured to support SGX-FLX 
  - Hyper-V VM with a special Ubuntu 16.04 image

##	Prerequisites 

  On your Windows/Linux host:
  
  - Install latest [Azure CLI 2.0](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest)(at least 2.0.43)
  - Download the OE-Engine, a tool that helps provision an SGX enabled Azure VM, and copy it to your local directory, 
    lets say D:\tools
  
     Windows: https://oejenkinsciartifacts.blob.core.windows.net/oe-engine/oe-engine.exe
     
     Linux: https://oejenkinsciartifacts.blob.core.windows.net/oe-engine/oe-engine


##	Provision an Azure SGX VM for Open Enclave application developers

-   Login to Azure portal by running the following Azure CLI command on your host

        az login

-   Set the default subscription for your account if it has multiple active subscriptions

        az account set --subscription "<subscription name>"
        
       For example:
        
          D:\tools> az account set --subscription "YourSubscriptionName"
           
- Deploy Using OE_ENGINE Deploy and prepare the VM

  - Create an API-model json file with the following contents and fill < > with DNS prefix and SSH key information 
 
        Create a simple api-model JSON file:
        {
          "properties": {
            "masterProfile": {
              "dnsPrefix": "<DNS prefix>",
              "vmSize": "Standard_DC2s"
            },
            "linuxProfile": {
              "adminUsername": "<YourUserName>",
              "ssh": {
                "publicKeys": [
                  {
                    "keyData": "fill here with your ssh public key here"
                  }
                ]
              }
            }
          }
        }
        
      For example: let's the api-model json file name is api-model.json
      
            D:\tools> dir
                  -a----         9/7/2018  10:39 PM            718 oe-engine-model.json
                  -a----         9/7/2018  10:30 PM        7447040 oe-engine.exe

            D:\tools> type .\oe-engine-model.json
            {
                "properties": {
                "masterProfile": {
                    "dnsPrefix": "mydns1001",
                    "vmSize": "Standard_DC2s"
                },
                "linuxProfile": {
                    "adminUsername": "azureuser",
                    "ssh": {
                    "publicKeys": [
                        {
                        "keyData": "ssh-rsa AAAA........"
                        }
                    ]
                    }
                }
                }
            }
        
    Note: The public key used above should be from the machine that you plan to ssh into the Azure VM once 
          the provision is done.
  
  - Generate ARM template

          oe-engine generate --api-model <api model filename from step #2>
 
    For example:
 
        D:\tools> .\oe-engine generate --api-model oe-engine-model.json
        INFO[0000] Generating assets into _output/mydns1001...
 
 - 	Create a resource group, for example youralias-acc-rg in `East US` region

            az group create -l eastus -n yourResourceGroupName

      For example:
      
            D:\tools> az group create -l eastus -n yourResourceGroupName
           
  - Deploy ACC VM

        $ az group deployment create --name <yourVMName> --resource-group <resource group name> 
                                     --template-file _output/<dnsPrefix>/azuredeploy.json 
                                     --parameters _output/<dnsPrefix>/azuredeploy.parameters.json
                                     
       For example:
       
         $ az group deployment create --name myAzureSGXVM --resource-group yourResourceGroupName --template-file _output/mydns1001/azuredeploy.json --parameters _output/mydns1001/azuredeploy.parameters.json

    It would take about ten minutes to provision such as an VM.
    
    Once completed,  ssh into the newly created VM by
 
        ssh YourUserName@<DNS prefix>.eastus.cloudapp.azure.com
        
    For example:
    
        D:\tools> ssh azureuser@mydns1001.eastus.cloudapp.azure.com

  
  The Acc Vm provided above is a SGX1 capable system (CoffeeLake). It comes with the Ubuntu 16.04-LTS 64-bits OS.
  And it also pre-installs Open Enclave SDK and all its runtime dependent components.

  
  There two types of audiences we are targeting here:
  
  - **Open Enclave application developers**: user intends to build/develop an OE application. 
  - **Open Enclave developers/builders** : users who not only want to experience OE applications but also want to dig into how OE was implemented, and potentially contribute to this open source effort, start here
  
  At this point, this ACC VM  is good for the Open Enclave application developers (build/develop an OE application).
  If your are a Open Enclave developers, you may want to continue to the next section for configuring it for Open Enclave development purpose. 
  
##	Make it a development environment for Open Enclave developers

### Obtain Open Enclave source code and install package dependencies

   - Clone Open Enclave SDK repository  from GitHub

       Use the following command to download the source distribution.

         $ git clone https://github.com/Microsoft/openenclave

        This creates a source tree under the directory called openenclave.

   - Install all the other prerequisites

      The  [scripts/install-prereqs script](/scripts/install-prereqs) script was created to make installing the prerequisites less tedious. Execute the following commands from the root of the source tree to install above prerequisites.

            $ cd openenclave
            $ sudo ./scripts/install-prereqs

### Build

To build, pick a directory to build under ("build/" below). Then use cmake to configure
the build and generate the make files and build.

```
$ mkdir build/
$ cd build/
build$ cmake .. -DUSE_LIBSGX=1
build$ make
```
### Run unittests

  After building, run all unit test cases via the following ctest command to confirm 
  SDK is built and working as expected.

```
build$ ctest
```
 
        You should see test log like the following:

        youradminusername@yourVMname:~/openenclave/build$  ctest

      Test project /home/youradminusername/openenclave/build
              Start   1: tests/aesm
        1/123 Test   #1: tests/aesm ...............................................................................................................   Passed    0.98 sec
              Start   2: tests/mem
        2/123 Test   #2: tests/mem ................................................................................................................   Passed    0.00 sec
              Start   3: tests/str
        3/123 Test   #3: tests/str ................................................................................................................   Passed    0.00 sec
      ....
      ....
      ....
      122/123 Test #122: tools/oedump .............................................................................................................   Passed    0.00 sec
              Start 123: oeelf
      123/123 Test #123: oeelf ....................................................................................................................   Passed    0.00 sec

      100% tests passed, 0 tests failed out of 123

      Total Test time (real) =  83.61 sec
      youradminusername@yourVMname:~/openenclave/build$

A clean pass of above unitests run is an indication that your Open Enclave setup was successful. You can start playing with those Open Enclave samples after following the instructions in the [Install](InstallInfo.md) section below to configure samples for building,



