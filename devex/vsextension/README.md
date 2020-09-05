# Visual Studio Extension for Open Enclave

This directory contains the source code for the Visual Studio Extension
for Open Enclave.

## Using the VS Extension

Documentation on acquiring and using the VS extension is at:

* [Using Visual Studio to Develop Enclave Applications for Linux](/docs/GettingStartedDocs/VisualStudioLinux.md)
* [Using Visual Studio to Develop Enclave Applications for Windows](/docs/GettingStartedDocs/VisualStudioWindows.md)

## Building the VS Extension from source

Visual Studio 2019 can be used to build the extension using the
VSExtension.sln solution file.

## Updating the VS Extension to use a newer Open Enclave SDK release

1. Create an `open-enclave-cross.<version info>.nupkg` derived from
   the `open-enclave.<version>.nupkg` asset that appears at
   https://github.com/openenclave/openenclave/releases, as follows:

   * TODO: update this with a better process after talking to Hernan
     to see what he actually does
   * Copy the following directories from the last open-enclave-cross
     nupkg:
         * build\native
         * lib\native
         * licenses
         * tools
   * Rename open-enclave.nuspec to open-enclave-cross.nuspec
     and update its contents to change the same string to add -cross

2. Update the OE SDK release version referenced.
   The OE SDK release number appears in a number of source files
   (as unfortunately currently there is no way to only configure it in
   one location).  Searching for "open-enclave-cross" in all files under
   this directory will find them.

## VS Extension Release Process

See [VS Extension Release Process](vsix-release-process.md).
