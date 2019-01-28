using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TemplateWizard;
using System.Windows.Forms;
using EnvDTE;
using System.IO;

namespace OpenEnclaveSDK
{
    public class WizardImplementation : IWizard
    {
        // This method is called before opening any item that   
        // has the OpenInEditor attribute.  
        public void BeforeOpeningFile(ProjectItem projectItem)
        {
        }

        public void ProjectFinishedGenerating(Project project)
        {
        }

        // This method is only called for item templates, not for project templates.  
        public void ProjectItemFinishedGenerating(ProjectItem projectItem)
        {
        }

        // This method is called after the project is created.  
        public void RunFinished()
        {
        }

        private bool SetOETADevKitPath(Dictionary<string, string> replacementsDictionary)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select ta_dev_kit.mk in your ARM TA Dev Kit, or hit Cancel to skip ARM support";
                openFileDialog.InitialDirectory = Directory.GetCurrentDirectory(); // Must be an absolute path.
                openFileDialog.Filter = "ta_dev_kit.mk|ta_dev_kit.mk";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    // Get the path of specified file.
                    var filePath = openFileDialog.FileName;
                    string folder = Path.GetFullPath(Path.Combine(filePath, "..\\.."));

                    // We now have the full path in Windows format, but we need to convert it to Unix format.
                    string root = Path.GetPathRoot(folder).ToLower();
                    string relativeFolder = folder.Substring(root.Length).Replace('\\', '/');
                    string drive = root.Substring(0, 1);
                    string unixPath = "/mnt/" + drive + "/" + relativeFolder;

                    replacementsDictionary.Add("$OETADevKitPath$", unixPath);
                    return true;
                }
            }
            return false;
        }

        private bool SetEnclaveName(Dictionary<string, string> replacementsDictionary)
        {
            try
            {
                // Get the $guid$1 value that has already been generated, and
                // create a struct version of it for use in code that needs it.
                string safeitemname;
                replacementsDictionary.TryGetValue("$safeitemname$", out safeitemname);

                // Extract enclave name.
                if (safeitemname.EndsWith("_host") && (safeitemname.Length > 5))
                {
                    string enclavename = safeitemname.Substring(0, safeitemname.Length - 5);

                    // Add $enclavename$.
                    replacementsDictionary.Add("$enclavename$", enclavename);
                }
                return true;
            } catch (Exception)
            {

            }
            return false;
        }

        public void RunStarted(
            object automationObject,
            Dictionary<string, string> replacementsDictionary,
            WizardRunKind runKind,
            object[] customParams)
        {
            try
            {
                // Get the $guid$1 value that has already been generated, and
                // create a struct version of it for use in code that needs it.
                string guid1;
                replacementsDictionary.TryGetValue("$guid1$", out guid1);

                /* Add $guid1struct$ */
                Guid guid1binary = Guid.Parse(guid1);
                string guid1struct = guid1binary.ToString("X");
                replacementsDictionary.Add("$guid1struct$", guid1struct);

                if (runKind == WizardRunKind.AsNewItem)
                {
                    SetEnclaveName(replacementsDictionary);
                }
                else
                {
                    SetOETADevKitPath(replacementsDictionary);

                    // In the future, we should prompt the user to select between:
                    // "vexpress-qemu_virt", "vexpress-qemu_armv8a", and
                    // ls-ls1012grapeboard.
                    string opteeBuildFlavor = "vexpress-qemu_armv8a";
                    replacementsDictionary.Add("$OpteeBuildFlavor$", opteeBuildFlavor);

                    // In the future, this should be "arm-linux-gnueabihf-" for any 32-bit build flavor.
                    string opteeCompilerFlavor = "aarch64-linux-gnu-";
                    replacementsDictionary.Add("$OpteeCompilerFlavor$", opteeCompilerFlavor);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        // This method is only called for item templates, not for project templates.  
        public bool ShouldAddProjectItem(string filePath)
        {
            return true;
        }
    }
}
