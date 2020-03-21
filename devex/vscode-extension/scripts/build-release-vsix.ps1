# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

Param(
    $aiKey,
    $packageFile = "package.json",
    [ValidateSet("no", "major", "minor", "patch")]
    $incrementVersion = "no",
    $resetAiKey = $true,
    $moveFolderLocation = $null
)

$originaldata = Get-Content -Raw -Path $packageFile | ConvertFrom-Json
$jsondata = $originaldata

#
# Handle Version incrementing
#
$version = $jsondata.version
if ([string]::isNullOrEmpty($version)) {
    $version = "0.0.1"
}
$versionData = $version.split('.')
if ($versionData.length -ne 3) {
    Write-Error "$packageFile has invalid version format.  Expecting numeric major.minor.patch"
    return;
}
switch ($incrementVersion) {
    ("major") { $jsondata.version = ([int]::parse($versionData[0]) + 1).toString() + ".0.0" }
    ("minor") { $jsondata.version = $versionData[0] + "." + ([int]::parse($versionData[1]) + 1).toString() + ".0" }
    ("patch") { $jsondata.version = $versionData[0] + "." + $versionData[1] + "." + ([int]::parse($versionData[2]) + 1).toString() }
}

$originalAiKey = $jsondata.aiKey

# Formats JSON in a nicer format than the built-in ConvertTo-Json does.
function Format-Json([Parameter(Mandatory, ValueFromPipeline)][String] $json) {
    $indent = 0;
    ($json -Split '\n' |
      % {
        if ($_ -match '[\}\]]') {
          # This line contains  ] or }, decrement the indentation level
          $indent--
        }
        $line = ("`t" * $indent) + $_.TrimStart().Replace(':  ', ': ')
        if ($_ -match '[\{\[]') {
          # This line contains [ or {, increment the indentation level
          $indent++
        }
        $line
    }) -Join "`n"
}

#
# Handle App Insights key modification
#
$jsondata.aiKey = $aiKey
$jsonData | ConvertTo-Json -depth 100| % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Format-Json | Set-Content $packageFile

$vsixFile = $jsonData.name + "-" + $jsondata.version + ".vsix"
Write-Host "Building VSIX pacakge: $vsixFile"
& vsce package | Out-String | Write-Host -ForegroundColor Green

if ($resetAiKey) {
    #
    # Reset App Insights key to original
    #
    $jsondata.aiKey = $originalAiKey
    $jsonData | ConvertTo-Json -depth 100| % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Format-Json | Set-Content $packageFile
}

if (![string]::IsNullOrEmpty($moveFolderLocation)) {
    $vsixPath = ".\$vsixFile"
    Write-Host "Moving $vsixPath to $moveFolderLocation"
    Move-Item -Path $vsixPath -Destination $moveFolderLocation -Force -Verbose | Out-String | Write-Host -ForegroundColor Green
}