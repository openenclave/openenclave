// Paste this script in Jenkins Script Console to configure Azure VM plugin
import com.microsoft.azure.vmagent.builders.*;

CLOUD_NAME="OE-ACC"
CREDENTIALS_ID_DOCKERREGISTRY="oejenkinscidockerregistry"
CREDENTIALS_ID_ADMIN="oeadmin-credentials"
CREDENTIALS_ID_VMSS="VMSSPrincipal"
AGENTS_STORAGE_ACCOUNT="agentsterraform"
AGENTS_RESOURCE_GROUP="OE-Jenkins-terraform"
AGENTS_LOCATION="West Europe"
AGENTS_IMAGE_PREFIX="/subscriptions/c4fdda6e-bfbd-4b8e-9703-037b3a45bf37/resourceGroups/OE-Jenkins-Terraform-Images/providers/Microsoft.Compute/images/"
VM_SIZE_SGX="Standard_DC2s"
VM_SIZE_NONSGX="Standard_D4s_v3"

def bionicTemplate = new AzureVMTemplateBuilder()
    .withName("accbionic")
    .withLabels("ACC-1804")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_SGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-bionic")
        .withInitScript("sudo gpasswd -a oeadmin docker \n" +
                        "sudo chmod g+rw /var/run/docker.sock")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();

def xenialTemplate = new AzureVMTemplateBuilder()
    .withName("accxenial")
    .withLabels("ACC-1604")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_SGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-xenial")
        .withInitScript("sudo gpasswd -a oeadmin docker \n" +
                        "sudo chmod g+rw /var/run/docker.sock")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();


def ubuntunonSGXTemplate = new AzureVMTemplateBuilder()
    .withName("ubuntunonsgx")
    .withLabels("nonSGX")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_NONSGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-ubuntu-nonSGX")
        .withInitScript("sudo gpasswd -a oeadmin docker \n" +
                        "sudo chmod g+rw /var/run/docker.sock")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();

def win2016Template = new AzureVMTemplateBuilder()
    .withName("accwin2016")
    .withLabels("SGXFLC-Windows")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_SGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-win2016")
        .withOsType("Windows")
        .withLaunchMethod("SSH")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();

def win2016dcapTemplate = new AzureVMTemplateBuilder()
    .withName("accwindcap")
    .withLabels("SGXFLC-Windows-DCAP")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_SGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-win2016-dcap")
        .withOsType("Windows")
        .withLaunchMethod("SSH")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();

def win2016nonSGXTemplate = new AzureVMTemplateBuilder()
    .withName("accwinnonsgx")
    .withLabels("nonSGX-Windows")
    .withLocation(AGENTS_LOCATION)
    .withVirtualMachineSize(VM_SIZE_NONSGX)
    .withExistingStorageAccount(AGENTS_STORAGE_ACCOUNT)
    .withUsageMode("Only build jobs with label expressions matching this node")
    .addNewAdvancedImage()
        .withCustomManagedImage(AGENTS_IMAGE_PREFIX + "terraform-win2016-nonSGX")
        .withOsType("Windows")
        .withLaunchMethod("SSH")
    .endAdvancedImage()
    .withAdminCredential(CREDENTIALS_ID_ADMIN)
    .build();


def myCloud = new AzureVMCloudBuilder()
    .withCloudName(CLOUD_NAME)
    .withAzureCredentialsId(CREDENTIALS_ID_VMSS)
    .withExistingResourceGroupName(AGENTS_RESOURCE_GROUP)
    .addToTemplates(bionicTemplate)
    .addToTemplates(xenialTemplate)
    .addToTemplates(ubuntunonSGXTemplate)
    .addToTemplates(win2016Template)
    .addToTemplates(win2016dcapTemplate)
    .addToTemplates(win2016nonSGXTemplate)
    .build();

Jenkins.getInstance().clouds.add(myCloud);
