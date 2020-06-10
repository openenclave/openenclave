# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

$usage=$false;
$quiet=$false;
$verbose=$false;
$whatif=$false;
[System.Collections.ArrayList]$userExcludeDirs=@();
[System.Collections.ArrayList]$userIncludeExts=@();
[System.Collections.ArrayList]$excludeDirs=@();
[System.Collections.ArrayList]$includeExts=@();
[System.Collections.ArrayList]$userFiles=@();


##==============================================================================
##
## Echo if verbose flag (ignores quiet flag)
##
##==============================================================================
function log_verbose()
{
    if ($verbose) {
        Write-Host "$args"
    }
}

##==============================================================================
##
## Echo if whatif flag is specified but not quiet flag
##
##==============================================================================
function log_whatif()
{
    if ( $whatif  -and -not $quiet)
    {
        Write-Host "$args"
    }
}

##==============================================================================
##
## Process command-line options
##
## Note that in Powershell syntex, fallthrough does not work as such,
## instead one must compare against multiple values.  For a discussion, see
## https://stackoverflow.com/questions/3493731/whats-the-powershell-syntax-for-multiple-values-in-a-switch-statement
##
##==============================================================================

foreach ($opt in $args)
{
  switch -regex ($opt) {

    { @("-h", "--help") -contains $_ }
        {
            $usage=$true;
            break;
        }

    { @("-q", "--quiet") -contains $_ }
        {
            $quiet=$true;
            break;
        }

    { @("-s", "--staged") -contains $_ }
        {
            $userFiles=(git diff --cached --name-only --diff-filter=ACMR);
            break;
        }

    { @("-v", "--verbose") -contains $_ }
        {
            $verbose=$true;
            break;
        }

    { @("-w", "--whatif") -contains $_ }
        {
            $whatif=$true;
            break;
        }

    "--exclude-dirs=*" {
            $userExcludeDirs=($opt -split "=")[1];
            break;
        }

    "--include-exts=*" {
            $userIncludeExts=($opt -split "=")[1];
            break;
        }

    "--files=*" {
            $userFiles=($opt -split "=")[1];
            break;
        }
    default {
            Write-Error "$PSCommandPath unknown option:  $opt"
            exit 1
            break;
        }
    }
}

##==============================================================================
##
## Display help
##
##==============================================================================

if ( $usage ) {
    $usageMessage = @'

OVERVIEW:

Formats all CMake files based on the .cmake-format rules

    $ format-cmake [-h] [-q] [-s] [-v] [-w] [--exclude-dirs="..."] [--include-exts="..."] [--files="..."]

OPTIONS:
    -h, --help              Print this help message.
    -q, --quiet             Display only cmake-format output and errors.
    -s, --staged            Only format files which are staged to be committed.
    -v, --verbose           Display verbose output.
    -w, --whatif            Run the script without actually modifying the files
                            and display the diff of expected changes, if any.
    --exclude-dirs          Subdirectories to exclude. If unspecified, then
                            ./3rdparty, ./build and ./prereqs are excluded.
                            All subdirectories are relative to the current path.
    --include-exts          File extensions to include for formatting. If
                            unspecified, then *.cmake and CMakeLists.txt are
                            included.
    --files                 Only run the script against the specified files from
                            the current directory.

EXAMPLES:

To determine what lines of each file in the default configuration would be
modified by format-cmake, you can run from the root folder:

    $ ./scripts/format-cmake -w

To update only CMake files in tests/ except for tests/echo/host, you
can run from the tests folder:

    tests$ ../scripts/format-cmake --exclude-dirs="echo/host"

To run only against a specified set of comma separated files in the current directory:

    $ ./scripts/format-cmake -w --files="file1 file2"

'@
    Write-Host "$usageMessage"
    exit 0
}

##==============================================================================
##
## Determine parameters for finding files to format
##
##==============================================================================
function get_find_args()
{
    $defaultExcludeDirs=@( ".git", "3rdparty", "prereqs", "build", "*.cquery_cached_index" );
    $defaultIncludeExts=@( "cmake" )

    $findargs='get-childitem -Recurse -Name "*" -Path "." '
    if ( !($userIncludeExts) ) {
        # not local as this is used in get_file_list() too
        $includeExts.AddRange($defaultIncludeExts)
    }
    else
    {
        log_verbose "Using user extension inclusions: $userIncludeExts"
        $includeExts.AddRange($userIncludeExts)
    }

    $findargs+=" -Include @( 'CMakeLists.txt', "
    foreach ($ext in $includeExts)
    {
        $findargs+=("'*."+"$ext'")
    }
    $findargs+=") "

    if (  !($userExcludeDirs) ) {
        $excludeDirs.AddRange($defaultExcludeDirs)
    }
    else {
        log_verbose "Using user directory exclusions: $userExcludeDirs"
        $excludeDirs.AddRange($userExcludeDirs)
    }

    $findargs+=" | where { "
    foreach ($dir in $excludeDirs)
    {
        $findargs+='$_ -notlike '
        $findargs+= "'$dir"+"\*'"
        if ($excludeDirs.IndexOf($dir) -lt $excludeDirs.count-1)
        {
            $findargs+=" -and  "
        }
    }
    $findargs+="} "

    return $findargs
}

function get_file_list()
{
    if ( !($userFiles) ) {
        $file_list = Invoke-Expression($findargs)
        if ( $file_list.count -eq 0 ) {
           Write-Host "No files were found to format!"
           exit 1
        }
    }
    else {
        log_verbose "Using user files: $userfiles"
        $file_list=@()
        foreach ( $file_name in $userfiles ) {
            $user_file_name = get-ChildItem -Path '.' -Name $file_name
            $file = New-Object System.IO.FileInfo($user_file_name)
            if ( $file_name -eq "CMakeLists.txt" ) {
                $file_list += $file_name
                log_verbose "Checking user file: $file_name"
            }
            else {
                foreach ( $ext in $includeExts ) {
                    if ( $file.Extension -match "$ext" ) {
                        $file_list += $file_name
                        log_verbose "Checking user file: $file_name"
                        break;
                    }
                }
            }
        }
    }
    return $file_list
}

$global:cf=""

##==============================================================================
##
## Check for installed cmake-format tool
##
##==============================================================================
function check_cmake-format()
{
    # Windows does not have a cmake-format-7 executable


    $required_cfver='0.6.9'

    try {
       $cfver=(cmake-format --version 2>&1)
    }
    catch {
        Write-Host "cmake-format not installed"
        return $false
    }

    $req_ver = $required_cfver -split '.'
    $cf_ver  = $cfver -split '.'

    for ($i = 0; $i -lt 3; $i++)
    {
        if ( $cf_ver[$i] -gt $req_ver[$i])
        {
            return $true
        }

        if ( $cf_ver[$i] -lt $req_ver[$i])
        {
            Write-Host "Required version of cmake-format is $required_cfver. Current version is $cfver"
            return $false
        }
        # Equal just keeps going
    }
    $global:cf="cmake-format"
    return $true
}


##==============================================================================
##
## Mainline: Call cmake-format for each file to be formatted
##
##==============================================================================

if (!(check_cmake-format)) # getting the filelist takes a few seconds. If we cant format we may as well exit now.
{
    exit -1
}

$findargs = get_find_args;
$filelist = get_file_list;
$filecount=0
$changecount=0

$cfargs="$global:cf"
if ( !$whatif ) {
    $cfargs="$cfargs -i"
}

foreach ( $file in $filelist ) {
    $filecount+=1;
    $cf="$cfargs $file"


    if ( $whatif ) {
        log_whatif "Formatting $file ..."
        ( Invoke-Expression ($cf) ) | Compare-Object (get-content $file)
    }
    else {
        if ( $verbose ) {
            log_verbose "Formatting $file ..."
            Invoke-Expression $cf
        }
        else {
            Invoke-Expression $cf > $null
        }
    }
    if ( $? ) {
        if ( $whatif ) {
            $changecount++
        }
    }
    else {
        Write-Host "cmake-format failed on file: $file."
    }
}

log_whatif "$filecount files processed, $changecount changed."

# If files are being edited, this count is zero so we exit with success.
exit $changecount
