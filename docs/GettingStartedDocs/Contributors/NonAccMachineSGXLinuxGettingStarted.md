# Configure OE SDK SGX on Linux in non-ACC Machines

## Disclaimer
This document is to provide a viable solution to enable Open Enclave SGX DCAP remote attestation to run on non-Azure Confidential Computing (ACC) machines. It relies on several Intel components and services which are subject to Intel's changes.

## 1. Platform requirements
- Ubuntu 18.04-LTS 64-bits (should also work on 16.04 LTS but hasn't been tested).
- SGX1 capable system with Flexible Launch Control support. This feature is only available on Intel Coffee Lake processor (8th gen) or newer.
- Strongly recommend to update your BIOS to newest version before start. With the setup described by this document, all attestation will be against the most recent collateral. Old BIOS versions, which may have lower CPU SVN, will cause attestation to fail.

## 2. Set up openenclave environment
### 2.1 Clone Open Enclave SDK repo from GitHub
Use the following command to download the source code.

```bash
git clone https://github.com/openenclave/openenclave.git
```

This creates a source tree under the directory called openenclave.

### 2.2 Install project requirements

First, change directory into the openenclave repository:
```bash
cd openenclave
```

Ansible is required to install the project requirements. If not already installed, you can install it by running:
```bash
sudo scripts/ansible/install-ansible.sh
```

Then run the following command to install the dependency:
```bash
ansible-playbook scripts/ansible/oe-contributors-setup.yml
```
NOTE: The Ansible playbook commands from above will try to execute tasks with sudo rights. Make sure that the user running the playbooks has sudo rights, and if it uses a sudo password add the following extra parameter --ask-become-pass.

## 3. Set up Intel DCAP Quote Provider Library (QPL):
### 3.1 Install Intel DCAP Quote Provider Library
To install Intel DCAP Quote Provider Library, you can choose to install it from the Intel SGX repository (recommended), or install it manually with dpkg.

- Install Intel DCAP Quote Provider Library from the Intel SGX APT repository

If you set up your environment by keeping following this documentation, then the Intel SGX APT source repository has been added. Directly run the following command to install it.

```bash
sudo apt install libsgx-dcap-default-qpl
```

NOTE: In case the Intel SGX APT source repository is not added to your system. Run the following commands to add it.

On Ubuntu 18.04:
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intelsgx.list
```

On Ubuntu 16.04:
```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu xenial main' | sudo tee /etc/apt/sources.list.d/intelsgx.list
```

Add the key to the list of trusted keys used by the apt to authenticate packages:
```bash
wget -qO - https://download.01.org/intelsgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
```

Update the apt
```bash
sudo apt-get update
```

- Or Install Intel DCAP Quote Provider with dpkg manually

The [libsgx-dcap-default-qpl directory](https://download.01.org/intel-sgx/sgx-dcap/1.6/linux/distro/ubuntuServer18.04/debian_pkgs/libs/libsgx-dcap-default-qpl/) lists all different version of libsgx-dcap-default-qpl, please download the most recent version that matches your OS version. For Ubuntu 18.04 (code name [Bionic Beaver](https://wiki.ubuntu.com/BionicBeaver)), please download the version libsgx-dcap-default-qpl_{version}-bionic1_amd64.deb. For Ubuntu 16.04 (code name [Xenial Xerus](https://wiki.ubuntu.com/XenialXerus)), please download the version libsgx-dcap-default-qpl_{version}-xenial1_amd64.deb.

In this document, we use libsgx-dcap-default-qpl_1.6.100.2-bionic1_amd64.deb as an example, run the command below to download the package
```bash
cd ~
wget https://download.01.org/intel-sgx/sgx-dcap/1.6/linux/distro/ubuntuServer18.04/debian_pkgs/libs/libsgx-dcap-default-qpl/libsgx-dcap-default-qpl_1.6.100.2-bionic1_amd64.deb
```

Then install the package
```bash
sudo dpkg -i libsgx-dcap-default-qpl_1.6.100.2-bionic1_amd64.deb
```

### 3.2 Create a soft link
OE expects the file name of the qpl to be libdcap_quoteprov.so. But the Intel default qpl creates installed libdcap_quoteprov.so.1 and libdcap_quoteprov.so.1.6.100.2.  libdcap_quoteprov.so.1 is a soft link to libdcap_quoteprov.so.1.6.100.2. To allow OE works properly, we need to create the other soft link called libdcap_quoteprov.s linking to libdcap_quoteprov.so.1.6.100.2

Check where those files are installed.
```bash
dpkg --listfiles libsgx-dcap-default-qpl
```

In most cases, it should be in /usr/lib/x86_64-linux-gnu/

Use /usr/lib/x86_64-linux-gnu/ as an example.
```bash
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s libdcap_quoteprov.so.1.6.100.2 libdcap_quoteprov.so
```

NOTES TO USERS WHO HAVE ALREADY INSTALLED AZURE DCAP CLIENT:

If you have Azure DCAP client installed before trying these instructions, please make sure the Azure one is renamed to something else.

To check if you have it installed, run the following command.
```bash
dpkg --list | grep az-dcap-client
```

If you don't have the Azure DCAP client installed previously, please skip the content below.

In most cases the Azure version of libdcap_quoteprov.so is located in /usr/lib. Check your path before changing. Here we use /usr/lib as an example.

```bash
sudo mv /usr/lib/libdcap_quoteprov.so /usr/lib/libdcap_quoteprov.so.azure
```

Otherwise the Azure one might still get used because $PATH might have /usr/lib before the path /usr/lib/x86_64-linux-gnu with the Intel version.

### 3.3 Configure the qpl
Edit the file /etc/sgx_default_qcnl.conf. To accept insecure HTTPS cert, set the option USE_SECURE_CERT to FALSE as we will use a local caching service which doesn't have a secure cert.

```bash
USE_SECURE_CERT=FALSE
```

Note:
The cert mentioned in /etc/sgx_default_qcnl.conf is just for a regular TLS handshaking between the QPL and the PCCS. That cert itself has nothing to do with attestation process. It has no relationship with the certs (e.g., Provisioning Certification Key certs (PCK certs)) that being used in the attestation.

Setting "USE_SECURE_CERT=FALSE" doesn't mean your attestation process is insecure. It just means QPL will accept a self-signed cert for TLS handshaking with PCCS. A CA-signed/self-signed cert might be a better word than a "secure/insecure" cert. But that's how exactly the /etc/sgx_default_qcnl.conf describes it. So we just document it accordingly.

## 4 Set up local Provisioning Certificate Caching Service (PCCS)
### 4.1 Register an Intel developer account and get a subscription key

If you don't have an Intel account, go to https://www.intel.com to register one by using the button at the corner.

![Intel Account](/docs/GettingStartedDocs/images/intel-account.png)

Sign in with your Intel account and then go to
https://api.portal.trustedservices.intel.com/provisioning-certification

You shall see the screen like this:

![Subscribe1](/docs/GettingStartedDocs/images/subscribe1.png)

Click the subscribe button then you shall see a page like this.

![Subscribe2](/docs/GettingStartedDocs/images/subscribe2.png)

Then click the subscribe button again. You shall see your subscription information.

![Primary Key](/docs/GettingStartedDocs/images/primary-key.png)

Get the value of your primary key, which will be used during PCCS service bring up.

### 4.2 Install and Config PCCS

Install nodejs and npm if you haven't

```bash
curl -sL https://deb.nodesource.com/setup_13.x | sudo -E bash
sudo apt-get install -y nodejs
```

To install PCCS, you can choose to install it from the Intel SGX repository (recommended), or install it manually with dpkg.

- Install PCCS from the Intel SGX repository
```bash
sudo apt install sgx-dcap-pccs
```
NOTE: In case the Intel SGX APT source repository is not added to your system. See how to add it in Section 3.1.

- Or Install PCCS with dpkg manually

From the [list of different versions of pccs](https://download.01.org/intel-sgx/sgx-dcap/1.6/linux/distro/ubuntuServer18.04/debian_pkgs/web/sgx-dcap-pccs/), please download the most recent version that matches your OS version.

In this document, we use sgx-dcap-pccs_1.6.100.2-bionic1_amd64.deb as an example.  Run the command below to download the package
```bash
cd ~
wget https://download.01.org/intel-sgx/sgx-dcap/1.6/linux/distro/ubuntuServer18.04/debian_pkgs/web/sgx-dcap-pccs/sgx-dcap-pccs_1.6.100.2-bionic1_amd64.deb
```

Then install the package.
```bash
sudo dpkg -i sgx-dcap-pccs_1.6.100.2-bionic1_amd64.deb
```

You will be asked to finish the configuration during the installation process.

![Config](/docs/GettingStartedDocs/images/config.png)

Recommended config:
- HTTPS listening port: use default value.
- Set the PCCS service to accept local connections only: use default value.
- Set your Intel Provisioning Certificate Service(PCS) API key: use the primary key of your subscription.
- Choose caching fill method: use default value.
- Set PCCS server administrator password: set your password
- Set PCCS server user password: set your password
- Do you want to generate insecure HTTPS key and cert for PCCS service?: Use default value and then in the following questions type in your info.

You can skip the following two items.
- A challenge password []:
- An optional company name []:

Then check the status of your service.
```bash
pm2 status
```
You should be able to see the service is running.
![nodejs](/docs/GettingStartedDocs/images/nodejs.png)

Run the following command to verify if it can actually fetch the root CA CRL from the Intel PCK service
```bash
curl --noproxy "*" -v -k -G "https://localhost:8081/sgx/certification/v2/rootcacrl"
```

To learn more about PCCS, please refer to the [PCCS GitHub repository](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/pccs).

## 5. Build and verify if the OE remote attestation works

### 5.1 Build
To build, first create a build directory ("build" in the example below) and change directory into it.

```bash
cd ~/openenclave/
mkdir build
cd build
```

Then run `cmake` to configure the build and generate the Makefiles, and then build by running `make` or 'ninja' depending:

```bash
cmake -G "Unix Makefiles" ..
make
```
or
```bash
cmake -G "Ninja" ..
ninja
```

After building, run all unit test cases using `ctest` to confirm the SDK is built and working as expected.

Run the following command from the build directory:

```bash
ctest
```

You will see test logs similar to the following:

```bash
~/openenclave/build$  ctest

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
```

A clean pass of the above unit tests is an indication that your Open Enclave setup was successful.
