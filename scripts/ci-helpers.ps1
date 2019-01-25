# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

function Start-ExternalCommand {
    <#
    .SYNOPSIS
    Helper function to execute a script block and throw an exception in case of error.
    .PARAMETER ScriptBlock
    Script block to execute
    .PARAMETER ArgumentList
    A list of parameters to pass to Invoke-Command
    .PARAMETER ErrorMessage
    Optional error message. This will become part of the exception message we throw in case of an error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Alias("Command")]
        [ScriptBlock]$ScriptBlock,
        [array]$ArgumentList=@(),
        [string]$ErrorMessage
    )
    PROCESS {
        if($LASTEXITCODE){
            # Leftover exit code. Some other process failed, and this
            # function was called before it was resolved.
            # There is no way to determine if the ScriptBlock contains
            # a powershell commandlet or a native application. So we clear out
            # the LASTEXITCODE variable before we execute. By this time, the value of
            # the variable is not to be trusted for error detection anyway.
            $LASTEXITCODE = ""
        }
        $res = Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        if ($LASTEXITCODE) {
            if(!$ErrorMessage){
                Throw ("Command exited with status: {0}" -f $LASTEXITCODE)
            }
            Throw ("{0} (Exit code: $LASTEXITCODE)" -f $ErrorMessage)
        }
        return $res
    }
}

function Set-VCVariables {
    Param(
        [string]$Version="15.0",
        [string]$Platform="amd64"
    )
    if($Version -eq "15.0") {
        $vcPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\"
    } else {
        $vcPath = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio $Version\VC\"
    }
    $vcVars = Start-ExternalCommand { cmd.exe /c "`"${vcPath}\vcvars64.bat`" $Platform & set" } -ErrorMessage "Failed to get all VC variables"
    $vcVars | Foreach-Object {
        if ($_ -match "=") {
            $v = $_.split("=")
            Set-Item -Force -Path "ENV:\$($v[0])" -Value "$($v[1])"
        }
    }
}
