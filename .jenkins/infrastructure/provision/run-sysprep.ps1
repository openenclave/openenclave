# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

$ErrorActionPreference = "Stop"

while ((Get-Service RdAgent).Status -ne 'Running') { Start-Sleep -s 5 }
while ((Get-Service WindowsAzureGuestAgent).Status -ne 'Running') { Start-Sleep -s 5 }

& $env:SystemRoot\System32\Sysprep\Sysprep.exe /oobe /generalize /quiet /quit
while ($true) {
    $imageState = Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State | Select ImageState
    if($imageState.ImageState -eq 'IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE') {
        break
    }
    Write-Output $imageState.ImageState
    Start-Sleep -s 10
}
