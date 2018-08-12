Function Write-Log
{
	param([Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]$Text,
		  
		  [Parameter(Mandatory=$true)]
          [ValidateSet("INFO", "WARNING", "ERROR")]
          [string]$Type
         )
		 
	$nowUTC = $(Get-Date).ToUniversalTime();
	$Message = "[{0:yyyy/MM/dd, HH:mm:ss:fff}]`t{1}`t{2}" -f $nowUTC, $Type, $Text;
	
	if($Global:LogFile)
	{
		Add-Content -Path $Global:LogFile $Message;
	}
	
	$color = (get-host).ui.rawui.ForegroundColor;
    #In ISE, above will set color to -1.  This is not an issue in regular powershell window.
    if($color -eq -1)
    {
        #Workaround for ISE window.
        $color = "White";   
    }

	if($Type -eq "WARNING")
	{
		$color = "yellow";
	}
	elseif($Type -eq "ERROR")
	{
		$color = "red";
	}
	Write-Host $Message -ForegroundColor $color;
}

Function IsStorageAccountInResourceGroup
{
    param([Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]$StorageAccountName,
          [Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]$ResourceGroupName
         )

    $StorageAccountList =  az storage account list --resource-group $ResourceGroupName | ConvertFrom-Json
    $StorageAccount = $StorageAccountList | Where-Object{$_.Name -eq $StorageAccountName};
    if($StorageAccount)
    {
        return $true;
    }
    else
    {
        return $false;
    }

}

Function UserPromptYesNo
{
    param([Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]$Message,
          [Parameter(Mandatory=$true)]
          [ValidateNotNullOrEmpty()]
          [string]$Question
         )

    $options = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $options.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $options.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))
    $result = $Host.UI.PromptForChoice($Message, $Question, $options, 1)
    return ($result -eq 0)
}





