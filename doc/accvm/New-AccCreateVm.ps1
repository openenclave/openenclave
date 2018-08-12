# Copyright (c) Microsoft Corporation. All rights reserved.

<#

The script is used to deploy ACC VMs using market place images publiished by ACC.

All images published by ACC use "microsoft-azure-compute" as Publisher name.
 
ACC market place images include

- Ubuntu 16.04:
            Offer:   azureconfidentialcompute
            Sku:     acc-ubuntu-16

- Windows Server 2016 with Visual Studio 2015 Professional:
            Offer:   azureconfidentialcompute
            Sku:     acc-windows-server-2016-vs 

- Note: The Open Enclave dev image is not supported by this script yet.

The script does the following
- Validate subscription
- Create and/or Validate Resource group
- Validate access to images.
- Accept terms of use for image.
- Deploy VM using image.
- For Linux VM, Port 22 is opened for SSH, For windows VM, Port 3389 is opened for RDP

Usage:

Create an ACC Linux VM (Assumes ssh keys will be used for auth)
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> -AccImage acc-ubuntu-16 -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmGenerateSSHKeys
Note: The SSH Keys will be stored in "~/.ssh" on linux and "%userprofile%\.ssh" on Windows

Create an ACC Linux VM with specified password
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> -AccImage acc-ubuntu-16 -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD>

Create an ACC Windows VM (If password is not specified, then script will prompt for password)
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> --AccImage acc-windows-server-2016-vs -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD>

Create an ACC VM with 4 cores (instead of default 2)
.\New-AccCreateVm.ps1 -Subscription <SUB_NAME_OR_ID> -ResourceGroupName <EXISTING_OR_NEW> --AccImage <ACC_IMAGE> -VMName <NAME_OF_VM> -VmUserName <NAME_OF_USER> -VmPassword <PASSWORD>  -VmSize Standard_DC4s

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Subscription,

    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory=$true)]
    [ValidateSet("acc-ubuntu-16", "acc-windows-server-2016-vs")]
    [string]$AccImage,

    [Parameter(Mandatory=$true)]
    [string]$VMName,

    [Parameter(Mandatory=$true)]
    [string]$VmUserName,

    [Parameter(Mandatory=$false)]
    [string]$VmPassword,

    [Parameter(Mandatory=$false)]
    [ValidateNotNullOrEmpty()]
    [switch]$VmGenerateSSHKeys,
       
    [Parameter(Mandatory=$false)]
    [ValidateSet("Standard_DC2s", "Standard_DC4s")]
    [string]$VmSize = "Standard_DC2s"
    )

. $PSScriptRoot\Utils.ps1

    
$NowUTC = $(Get-Date).ToUniversalTime()
$Global:LogFile = ($PSScriptRoot + "\New-AccCreateVmImageLog-" + "{0:yyyy.MM.dd.HH.mm.ss.fff}.log") -f $NowUTC

$ParameterString = @"
                          `t    `tSubscription: $Subscription
                          `t    `tResourceGroupName: $ResourceGroupName
                          `t    `tAccImage: $AccImage
                          `t    `tVmName: $VmName
                          `t    `tVmUsername: $VmUserName
                          `t    `tVmSize: $VmSize
"@

Write-Log -Type INFO -Text "Log File: $($Global:LogFile)";
Write-Log -Type INFO -Text "New ACC VM:`r`n$ParameterString"

# Constants 
$Location = "eastus"
$TargetContainerName = "accvhds"
$ParameterNameVmPassword = "VmPassword"
$ParameterNameVmGenerateSSHKeys = "VmGenerateSSHKeys"
$GeneralizedString = "Generalized"

$LinuxString = "linux"
$WindowsString = "windows"
$NsgRuleWindows = "RDP"
$NsgRuleLinux = "SSH"

# Image details

$PublisherName = "microsoft-azure-compute"

$Offer_UbuntuBase = "azureconfidentialcompute"
$Sku_UbuntuBase = "acc-ubuntu-16"

$Offer_Windows = "azureconfidentialcompute"
$Sku_Windows = "acc-windows-server-2016-vs"

$Offer_UbuntuDev = "azureconfidentialcompute"
$Sku_UbuntuDev = "acc-ubuntu-dev"

if($AccImage -eq "acc-ubuntu-16")
{
    $Offer = $Offer_UbuntuBase
    $Sku = $Sku_UbuntuBase
    $ImageOsType = $LinuxString
    $NsgRule = $NsgRuleLinux
}
elseif($AccImage -eq "acc-windows-server-2016-vs")
{
    $Offer = $Offer_Windows
    $Sku = $Sku_Windows
    $ImageOsType = $WindowsString
    $NsgRule = $NsgRuleWindows
}
elseif($AccImage -eq "acc-ubuntu-dev")
{
    Write-Log -Type ERROR -Text "AccImage: $AccImage not supported through the marketplace."
    exit

    $Offer = $Offer_UbuntuDev
    $Sku = $Sku_UbuntuDev
    $ImageOsType = $LinuxString
    $NsgRule = $NsgRuleLinux
}
else
{
    Write-Log -Type ERROR -Text "AccImage: $AccImage not supported through the marketplace."
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

$ImageUrn = "$PublisherName`:$Offer`:$Sku`:latest"

$image = az vm image show --location $Location --urn $ImageUrn | ConvertFrom-Json

if(-not $image)
{
    Write-Log -Type ERROR -Text "It seems that the subscription $Subscription does not have access to the marketplace image: $sku.  Please reach out to your ACC contact for support."
    exit
}

$terms = az vm image accept-terms --urn $ImageUrn | ConvertFrom-Json

if(-not $terms.accepted)
{
    # Image terms not accepted, This is unexpected.
    Write-Log -Type ERROR -Text "Error in programmatically accepting licensing terms for the image: $Sku"
    exit
}

$UseSSHKeysForAuth = $false

if($ImageOsType -eq $LinuxString -and (-not $params.ContainsKey($ParameterNameVmPassword) -or $params.ContainsKey($ParameterNameVmGenerateSSHKeys)))
{
    # For Linux VMs, we default to using SSH keys.  So we will create VM with SSH Keys if no password is specified or user explictly requests SSH Keys
    $Vm_Object = az vm create --name $VMName --resource-group $ResourceGroupName --size $VmSize --admin-username $VmUserName --generate-ssh-keys --image $ImageUrn --location $Location --nsg-rule $NsgRule | ConvertFrom-Json
    $UseSSHKeysForAuth = $true
}
else
{
    $Vm_Object = az vm create --name $VMName --resource-group $ResourceGroupName --size $VmSize --admin-username $VmUserName --admin-password $VmPassword --image $ImageUrn --location $Location --nsg-rule $NsgRule | ConvertFrom-Json
        
    # It seems that NSG rule for RDP is not being created for windows VMs when created using ACC windows private image and CLI
    # Add a rule to expose RDP endpoint for windows VMs
    if($ImageOsType -eq $WindowsString)
    {
        Write-Log -Type INFO -Text "Opening RDP Port 3389 for VM: $VMName."
        $nsgrules = az vm open-port --name $VMName --port 3389 --resource-group $ResourceGroupName | ConvertFrom-Json
    }
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
