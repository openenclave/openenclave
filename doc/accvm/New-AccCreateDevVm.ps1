# Copyright (c) Microsoft Corporation. All rights reserved.

<#

The script is used to deploy ACC VMs using image uris publiished by ACC.  This script is to be used if and when the market places images published by ACC are not accessible.
The script does the following
- Copy images from ACC source URIs to target storage account
- Generate a managed disk and subsequently an image object within the account.
- Deploy VM using the created image.
  Note: Subsequent calls to New-AccCreateVm will use existing image object (if created already) 

Usage:

Create an ACC Dev VM with existing storage account
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> -StorageAccountName <EXISTING_STORAGE_ACCOUNT> -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD>

Create an ACC Dev VM with new storage account
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> -StorageAccountName <NEW_STORAGE_ACCOUNT> -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD> -CreateStorageAccount

Create an ACC Dev VM with 4 cores (instead of dafault: 2)
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> -StorageAccountName <EXISTING_STORAGE_ACCOUNT> -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD> -VmSize Standard_DC4s

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Subscription,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,
       
    [Parameter(Mandatory=$false)]
    [ValidateSet("acc-ubuntu-dev")]
    [string]$AccImage = "acc-ubuntu-dev",

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [Parameter(Mandatory=$true)]
    [string]$VmUserName,

    [Parameter(Mandatory=$true)]
    [string]$VmPassword,

    [Parameter(Mandatory=$false)]
    [ValidateSet("Standard_DC2s", "Standard_DC4s")]
    [string]$VmSize = "Standard_DC2s",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Premium_LRS", "Standard_LRS")]
    [string]$StorageAccountSku = "Premium_LRS",
    
    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$CreateStorageAccount
    
    )

. $PSScriptRoot\Utils.ps1

# Excluded parameters
$VmGenerateSSHKeys = $false;

   
$NowUTC = $(Get-Date).ToUniversalTime()
$Global:LogFile = ($PSScriptRoot + "\New-AccCreateVmImageLog-" + "{0:yyyy.MM.dd.HH.mm.ss.fff}.log") -f $NowUTC

$ParameterString = @"
                          `t    `tSubscription: $Subscription
                          `t    `tResourceGroupName: $ResourceGroupName
                          `t    `tStorageAccountName: $StorageAccountName
                          `t    `tAccImage: $AccImage
                          `t    `tVmName: $VmName
                          `t    `tVmUsername: $VmUserName
                          `t    `tVmSize: $VmSize
"@

Write-Log -Type INFO -Text "Log File: $($Global:LogFile)";
Write-Log -Type INFO -Text "Creating New ACC VM:`r`n$ParameterString"

if($VmUserName -eq "accuser" -and $AccImage -eq "acc-ubuntu-dev")
{
    Write-Log -Type ERROR -Text "For now, accuser is reserved username for the dev image.  Please use an alternative username and try again."
	exit
}

# Constants 
$Location = "eastus"
$TargetContainerName = "accvhds"
$ParameterNameVmPassword = "VmPassword"
$ParameterNameVmGenerateSSHKeys = "VmGenerateSSHKeys"
$GeneralizedString = "Generalized"

$LinuxString = "Linux"
$WindowsString = "Windows"

# Image details

$ImageUri_UbuntuBase = '"https://accpublishedimages.blob.core.windows.net/privatepreviewimages/ACC-BASE-UBUNTU-16.04.3-Gen1Gen2-32GB-Generalized.vhd?sp=r&st=2018-06-01T00:00:00Z&se=2018-12-31T23:59:59Z&spr=https&sv=2017-11-09&sig=aFahJyQhb8uS%2Fa46UewLyG1F0kd0UhgQHMpjTmbKkV4%3D&sr=b"'
$TargetBlobName_UbuntuBase = "Acc-Ubuntu-16-04.vhd"
$TargetDiskName_UbuntuBase = "Acc-Ubuntu-16-04-OSDisk"
$TargetImageName_UbuntuBase = "AccUbuntuImg"


$ImageUri_Windows = '"https://accpublishedimages.blob.core.windows.net/privatepreviewimages/ACC-BASE-WS16-20180612-128GB-VSO-PSW-Generalized-Tag.vhd?sp=r&st=2018-06-01T00:00:00Z&se=2018-12-31T23:59:59Z&spr=https&sv=2017-11-09&sig=qtGyxJIEn0qPNtRNTGTnJm%2Fln%2FpCb5hi9NumfH1llns%3D&sr=b"'
$TargetBlobName_Windows = "Acc-WindowsServer-2016-VS.vhd"
$TargetDiskName_Windows = "Acc-WindowsServer-2016-VS-OSDisk"
$TargetImageName_Windows = "AccWindowsImg"

$ImageUri_UbuntuDev = '"https://accpublishedimages.blob.core.windows.net/privatepreviewimages/ACC-DEV-UBUNTU-16.04.3-XENIAL-32GB-Generalized.vhd?sp=r&st=2018-06-01T00:00:00Z&se=2018-12-31T23:59:59Z&spr=https&sv=2017-11-09&sig=HLNcDlS39zF2xxZZZx4ZWD338g7Ipm1c7j4hdlx0lIA%3D&sr=b"'
$TargetBlobName_UbuntuDev = "Acc-Ubuntu-Dev.vhd"
$TargetDiskName_UbuntuDev = "Acc-Ubuntu-Dev-OSDisk"
$TargetImageName_UbuntuDev = "AccDevImg"

if($AccImage -eq "acc-ubuntu-16-04")
{
    $ImageUri = $ImageUri_UbuntuBase
    $TargetBlobName = $TargetBlobName_UbuntuBase
    $TargetImageName = $TargetImageName_UbuntuBase
    $TargetDiskName = $TargetDiskName_UbuntuBase
    $ImageOsType = $LinuxString
}
elseif($AccImage -eq "acc-windows-server-2016-vs")
{
    $ImageUri = $ImageUri_Windows
    $TargetBlobName = $TargetBlobName_Windows
    $TargetImageName = $TargetImageName_Windows
    $TargetDiskName = $TargetDiskName_Windows
    $ImageOsType = $WindowsString
}
elseif($AccImage -eq "acc-ubuntu-dev")
{
    $ImageUri = $ImageUri_UbuntuDev
    $TargetBlobName = $TargetBlobName_UbuntuDev
    $TargetImageName = $TargetImageName_UbuntuDev
    $TargetDiskName = $TargetDiskName_UbuntuDev
    $ImageOsType = $LinuxString
}
else
{
    Write-Log -Type ERROR -Text "AccImage: $AccImage not supported."
    exit
} 


# Validate Subscription name/id

$SubscriptionObject = az account show --subscription $Subscription | ConvertFrom-Json
if(-not $SubscriptionObject)
{
    Write-Log -Type ERROR -Text "Subscription: $Subscription not found for existing account. Please run `"az login`" to login with right credentials."
    exit
}

# Set as Current Subscription
az account set --subscription $Subscription

# Create or Validate Resource Group 

if(-not (az group exists --name $ResourceGroupName | ConvertFrom-Json))
{
    Write-Log -Type INFO -Text "Creating Resource Group: $ResourceGroupName in Subscription: $Subscription."

    $ResourceGroupObject = az group create --name $ResourceGroupName --location $Location | ConvertFrom-Json
    if($ResourceGroupObject.properties.provisioningState -ne "Succeeded")
    {
        Write-Log -Type ERROR -Text "Could not create new ResourceGroup: $ResourceGroupName in Subscription: $Subscription."
        exit
    }

    Write-Log -Type INFO -Text "Created."
}
else
{
    $ResourceGroupObject = az group show --name $ResourceGroupName | ConvertFrom-Json
    if($ResourceGroupObject.location -ne $Location)
    {
        # Resource group creation failed.
        Write-Log -Type ERROR -Text "Resource group: $ResourceGroupName is in incorrect location.  Current value: $($ResourceGroupObject.location), Expected: $Location."
        exit
    }

}

#Create or Validate Image

$ImageObject = az image show --name $TargetImageName --resource-group $ResourceGroupName | ConvertFrom-Json

if(-not $ImageObject)
{

    #Create or Validate Storage account.

    if(-not (IsStorageAccountInResourceGroup -StorageAccountName $StorageAccountName -ResourceGroupName $ResourceGroupName))
    {
        #Storage account not found within resource group
        if($CreateStorageAccount)
        { 
            #Check if storage account name is available and valid  
            $StorageAccountCheck = az storage account check-name --name $StorageAccountName | ConvertFrom-Json

            if($StorageAccountCheck.nameAvailable -eq "true")
            {
                Write-Log -Type INFO -Text "Creating storage account: $StorageAccountName in Subscription: $Subscription and Resource Group: $ResourceGroupName."

                # If storage account name is valid, create storage account.
                $StorageAccountObject = az storage account create --name $StorageAccountName --resource-group $ResourceGroupName --location $Location --sku $StorageAccountSku --kind Storage | ConvertFrom-Json
                if($StorageAccountObject.provisioningState -ne "Succeeded")
                {
                    # Storage account creation failed.
                    Write-Log -Type ERROR -Text "Could not create Storage account: $StorageAccountName in Subscription: $Subscription and Resource Group: $ResourceGroupName."
                    exit
                }

                Write-Log -Type INFO -Text "Created."
            }
            else
            {
                # Issues with storage account name
                Write-Log -Type ERROR -Text "Cannot create Storage account: $StorageAccountName in Subscription: $Subscription and Resource Group: $ResourceGroupName. Reason: $($StorageAccountCheck.reason), Message: $($StorageAccountCheck.message)."
                exit
            }
        }
        else
        {
            # Storage account not found, quit.
            Write-Log -Type ERROR -Text "Storage account: $StorageAccountName not found in Subscription: $Subscription and Resource Group: $ResourceGroupName. Please use -CreateStorageAccount to create a new storage account."
            exit
        }
    }
    else
    {
        # Validate storage account

        $StorageAccountObject = az storage account show --name $StorageAccountName --resource-group $ResourceGroupName | ConvertFrom-Json
        if($StorageAccountObject.location -ne $Location)
        {
            Write-Log -Type ERROR -Text "Storage account: $StorageAccountName is in incorrect region. Current Value: $($StorageAccountObject.location), Expected Value: $Location."
            exit
        }

        <#
        if($StorageAccountObject.sku.tier -ne "Premium")
        {
            Write-Log -Type WARNING -Text "Storage account: $StorageAccountName is not in premium tier. This may impact performance."
        }
        #>
    }

    $StorageAccountConnectionString = (az storage account show-connection-string --name $StorageAccountName --resource-group $ResourceGroupName | ConvertFrom-Json).connectionString

    #Create Container
    
    $DoesTargetContainerExists = (az storage container exists --name $TargetContainerName --connection-string $StorageAccountConnectionString | ConvertFrom-Json).exists
    if(-not $DoestargetContainerExists)
    {
        Write-Log -Type INFO -Text "Creating container: $TargetContainerName in Storage account: $StorageAccountName."
        $ContainerCreationSuccess = (az storage container create --name $TargetContainerName --connection-string $StorageAccountConnectionString | ConvertFrom-Json).created

        if(-not $ContainerCreationSuccess)
        {
            Write-Log -Type ERROR -Text "Could not create Container: $TargetContainerName in Storage account: $StorageAccountName."
            exit
        }

        Write-Log -Type INFO -Text "Created."
    }
    
    # Copy ACC image from to target container

    $StorageBlobCopy = az storage blob copy start --source-uri $ImageUri --connection-string $StorageAccountConnectionString --destination-container $TargetContainerName --destination-blob $TargetBlobName | ConvertFrom-Json

    Write-Log -Type INFO -Text "Image copy initiated: $AccImage"

    do
    {
        $StorageBlobCopy = (az storage blob show --name $TargetBlobName --container-name $TargetContainerName --connection-string $StorageAccountConnectionString | ConvertFrom-Json).properties.copy
        $ProgressString = $StorageBlobCopy.progress;
        $ProgressStringSplit = $ProgressString.IndexOf('/')
        if($ProgressStringSplit -ne -1)
        {
            $Percentage = [double]($ProgressString.Substring(0, $ProgressStringSplit)) / [double]($ProgressString.Substring($ProgressStringSplit+1)) * 100;
            Write-Progress -Activity "Image copy in progress." -Status "$ProgressString" -PercentComplete $Percentage
        }
        Write-Host -NoNewline "."
        Start-Sleep -Seconds 2
    }
    While($StorageBlobCopy.status -ne "success")

    Write-Progress -Activity "Image copy in progress." -Status "$ProgressString" -PercentComplete $Percentage -Completed
    Write-Host ""

    Write-Log -Type INFO "Image: $AccImage copied.  Completion time: $($StorageBlobCopy.completionTime)." 

    $TargetImageUri = az storage blob url --name $TargetBlobName --container-name $TargetContainerName --connection-string $StorageAccountConnectionString | ConvertFrom-Json
    
    # Create Managed disk and Image object using the newly copied acc image.

    Write-Log -Type INFO -Text "Creating managed disk: $TargetDiskName in Resource Group: $ResourceGroupName."
    $ImageDiskObject = az disk create --resource-group $ResourceGroupName --name $TargetDiskName --source $TargetImageUri --sku $StorageAccountSku | ConvertFrom-Json
    if($ImageDiskObject.provisioningState -ne "Succeeded")
    {
        Write-Log -Type ERROR -Text "Could not create managed disk: $TargetDiskName in Resource Group: $ResourceGroupName."
        exit
    }
    Write-Log -Type INFO -Text "Created."


    Write-Log -Type INFO -Text "Creating image: $TargetImageName in Resource Group: $ResourceGroupName."
    $ImageObject = az image create --resource-group $ResourceGroupName --location $Location --name $TargetImageName --os-type $ImageOsType --source $TargetDiskName | ConvertFrom-Json
    if($ImageObject.provisioningState -ne "Succeeded")
    {
        Write-Log -Type ERROR -Text "Could not create image: $TargetImageName in Resource Group: $ResourceGroupName."
        exit
    }
    Write-Log -Type INFO -Text "Created."
}
else
{
    # Validate image

    if($ImageObject.location -ne $Location)
    {
        Write-Log -Type ERROR -Text "Image: $TargetImageName is in incorrect region. Current Value: $($ImageObject.location), Expected Value: $Location."
        exit
    }

    if($ImageObject.storageProfile.osDisk.osType -ne $ImageOsType)
    {
        Write-Log -Type ERROR -Text "Image: $TargetImageName is of incorrect type. Current Value: $($ImageObject.storageProfile.osDisk.osType), Expected Value: $ImageOsType."
        exit
    }

    if($ImageObject.storageProfile.osDisk.osState -ne $GeneralizedString)
    {
        Write-Log -Type ERROR -Text "Image: $TargetImageName is in incorrect state. Current Value: $($ImageObject.storageProfile.osDisk.osState), Expected Value: $GeneralizedString."
        exit
    }       
}

# For windows vms, we require a password, prompt if not specifed
$params = $MyInvocation.BoundParameters;
if($ImageOsType -eq $WindowsString -and -not $params.ContainsKey($ParameterNameVmPassword))
{
    $cred = Get-Credential -UserName $VmUserName -Message "Specify credentials for your windows Vm."
    $VmPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password));
	
	if(-not $VmPassword)
    {
        Write-Log -Type ERROR -Text "No password specified. Windows VMs require a password. Exiting."
        exit
    }
}

Write-Log -Type INFO -Text "Creating $ImageOsType Vm: $VmName of VmSize: $VmSize."

$UseSSHKeysForAuth = $false

if($ImageOsType -eq $LinuxString -and (-not $params.ContainsKey($ParameterNameVmPassword) -or $params.ContainsKey($ParameterNameVmGenerateSSHKeys)))
{
    # For Linux VMs, we default to using SSH keys.  SO we will create VM with SSH Keys if no password is specified or user explictly requests SSH Keys
    $Vm_Object = az vm create --name $VMName --resource-group $ResourceGroupName --size $VmSize --admin-username $VmUserName --generate-ssh-keys --image $TargetImageName --location $Location | ConvertFrom-Json
	$UseSSHKeysForAuth = $true
}
else
{
    $Vm_Object = az vm create --name $VMName --resource-group $ResourceGroupName --size $VmSize --admin-username $VmUserName --admin-password $VmPassword --image $TargetImageName --location $Location | ConvertFrom-Json
}

$VmPassword = "";


if($Vm_Object.publicIpAddress)
{
    Write-Log -Type INFO -Text "VM Created: $VmName, Public IP: $($Vm_Object.publicIpAddress)"
    if($UseSSHKeysForAuth)
    {
        Write-Log -Type INFO -Text "SSH keys can be found in Linux: ~/.ssh, Windows: %userprofile%\.ssh."
    }
}
else
{
    Write-Log -Type ERROR -Text "VM Creation failed."
}

