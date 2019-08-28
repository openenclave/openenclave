Windows
================

This folder contains an example `oesdk.nuspec` to illustrate what a nuspec for OE SDK on Windows might look like.
It can be built from this folder with the `nuget.exe` tool, which can be downloaded from:
https://www.nuget.org/api/v2/package/NuGet.exe/3.4.3.

You can rename the `nuget.exe.3.4.3.nupkg` file to the `.zip` extension and manually extract the `nuget.exe`
into this folder. You can then run:

```cmd
nuget pack oesdk.nuspec
```

This should produce `OpenEnclave.SDK.0.7.0.nupkg` in your local path. You can then also rename that to `.zip`
to explore its contents, or install it into the file system:

```cmd
nuget.exe install OpenEnclave.SDK -source <full path to folder containing .nupkg> -OutputDirectory .\nuget
```