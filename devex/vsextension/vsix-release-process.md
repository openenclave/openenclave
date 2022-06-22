# VS Extension Release Process

The process used to build and release the nuget package from these
sources is as follows.  Currently the signature on the release is
a Microsoft signature generated using the Microsoft [PODSS](https://aka.ms/podss) process.
In the future, this process will change to a use a non-Microsoft
signature once another signing process is defined for Open Enclave.

1. Take note of the latest published version of the [Cross-Platform Open Enclave SDK NuGet Package](https://www.nuget.org/packages/open-enclave-cross). The latest published
   version of the package should be used when building the VS Extension.

2. In the steps below, modify the references to the Cross-Platform Open Enclave
   SDK NuGet Package. During the build process, the package will be [downloaded](https://github.com/openenclave/openenclave/blob/master/devex/vsextension/ProjectWizard/VSExtension.csproj#L490)
   into your local `openenclave\devex\vsextension\ProjectWizard\Packages\`
   directory in the open-enclave repository, where the VS extension solution
   will look for it.

3. Make a note of the old version referenced in the VS extension sources.
   This can be found by running the following in the
   `openenclave\devex\vsextension` directory of the open-enclave repository:

      ```cmd
      findstr open-enclave-cross ProjectWizard\source.extension.vsixmanifest
      ```

4. Update the open-enclave-cross version referenced in the VS extension
   sources. For example, from a bash prompt, to update from
   0.8.1-c3b6262c-3 to 0.11.0-rc1-cbe4dedc-1:

      ```bash
      grep -RiIl '0.8.1-c3b6262c-3' | xargs sed -i 's/0.8.1-c3b6262c-3/0.11.0-rc1-cbe4dedc-1/g'
      ```

5. Bump the Identity Version number in the ProjectWizard\source.extension.vsixmanifest
   file (0.7.29 in the example below). By convension, the major and minor version
   number should match those of open-enclave-cross, and the patch
   number should be monotonically increasing (e.g., go from 0.7.29 to 0.8.30).

      ```
      <Identity Id="OpenEnclaveVisualStudioExtension-1" Version="0.7.29" Language="en-US" Publisher="Microsoft" />
      ```

6. Open VSExtension.sln in VS2019 and run code analysis on the solution
   (Analyze -> Run Code Analysis -> On Solution) and verify there's no
   errors or warnings.

7. Build the Release configuration.

8. Copy the vsix file to a new directory (e.g., a "publish" directory under
   the Release directory).  Make sure there's nothing else in that directory.

9. Generate a PODSS codesign request that references that directory as follows:

    ```cmd
    PODSSClientCore.exe Sign -a "<comma-separated list of authorized approver usernames>" -s "<full path to the publish directory used in step 4>" -dn "Open Enclave VSIX" -du "https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/visualstudio_dev.md" -c "100040160"
    ```

    * So far the following are authorized approvers: dthaler, anakrish, radhikaj

    * The status can be checked at https://dev.azure.com/esrptools/sign/_git/signv2/pullrequests?_a=mine

10. Once there are 2 other approvers besides you, the task will run and you
   will be emailed a link to get the result, e.g.,
   `https://dev.azure.com/esrptools/sign/_build/results?buildId=2253`
   if the job number was 2253.  From that link, click on
   "1 published; 1 consumed", and
   download the signed OpenEnclaveSDK.vsix file.

11. Upload the result to the VS marketplace as follows:

    1. Sign in at https://marketplace.visualstudio.com/

    2. Click "Publish extensions".

    3. Click the "..." next to Open Enclave - Preview, and select Edit.

    4. Click the pencil icon under the "1. Upload extension" section and
       upload the newly signed binary.

    5. Verify that the Version info shows the updated version number.

    6. Click the "Save & Upload" button at the bottom of the page.
       The resulting page will show as Verifying and then finally as Public.

    7. Verify the result at https://marketplace.visualstudio.com/items?itemName=MS-TCPS.OpenEnclaveSDK-VSIX
