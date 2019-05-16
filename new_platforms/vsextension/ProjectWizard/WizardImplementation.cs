using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TemplateWizard;
using System.Windows.Forms;
using EnvDTE;
using System.IO;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;

namespace OpenEnclaveSDK
{
    public class WizardImplementation : IWizard
    {
        public static string EdlLocation;

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

        // Look in <folder>/conf.mk for CFG_TA_FLOAT_SUPPORT := y
        // to see if hardware float support is enabled.
        private bool IsHardwareFloatSupported(string folder)
        {
            try
            {
                string fileName = Path.Combine(folder, "mk\\conf.mk");
                var lines = File.ReadLines(fileName);
                foreach (var line in lines)
                {
                    if (!line.Contains("CFG_TA_FLOAT_SUPPORT"))
                    {
                        continue;
                    }

                    return line.TrimEnd().EndsWith("y");
                }
                return false;
            }
            catch (IOException e)
            {
                return false;
            }
        }

        private bool SetOETADevKitPath(Dictionary<string, string> replacementsDictionary)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // First try picking the board from a menu.
            BoardPickerPage picker = new BoardPickerPage();
            DialogResult result = picker.ShowDialog();
            if (result != DialogResult.OK || picker.Board == "None")
            {
                // No ARM support requested.
                return false;
            }

            string folder = null;
            string board = picker.Board;
            if (board != "Other")
            {
                // User picked a specific board for which we have a TA Dev Kit in the nuget package.
                string solutionDirectory;
                replacementsDictionary.TryGetValue("$solutiondirectory$", out solutionDirectory);
                folder = Path.Combine(solutionDirectory, "packages\\openenclave.0.2.0-CI-20190409-193849\\lib\\native\\gcc6\\optee\\v3.3.0\\" + board);
            }
            else
            {
                // Ok, the user picked "Other", so ask the user for their own TA Dev Kit location.
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Title = "Select ta_dev_kit.mk in your ARM TA Dev Kit, or hit Cancel to skip ARM support";
                    openFileDialog.InitialDirectory = Directory.GetCurrentDirectory(); // Must be an absolute path.
                    openFileDialog.Filter = "ta_dev_kit.mk|ta_dev_kit.mk";
                    openFileDialog.RestoreDirectory = true;

                    if (openFileDialog.ShowDialog() != DialogResult.OK)
                    {
                        return false;
                    }

                    // Get the path of specified file.
                    string filePath = openFileDialog.FileName;
                    folder = Path.GetFullPath(Path.Combine(filePath, "..\\.."));
                }
            }

            // We now have the full path in Windows format, but we need to convert it to Unix format.
            string root = Path.GetPathRoot(folder).ToLower();
            string relativeFolder = folder.Substring(root.Length).Replace('\\', '/');
            string drive = root.Substring(0, 1);
            string unixPath = "/mnt/" + drive + "/" + relativeFolder;

            replacementsDictionary.Add("$OETADevKitPath$", unixPath);

            // 'folder' now contains the full path to the export-ta_arm{32,64} directory.
            // From this path, determine the compiler from the last path segment, and
            // the build flavor from the next-to-last path segment.

            string[] pathComponents = folder.Split('\\');
            if (pathComponents.Length < 2)
            {
                return false;
            }
            string buildFlavor = pathComponents[pathComponents.Length - 2];
            replacementsDictionary.Add("$OpteeBuildFlavor$", buildFlavor);

            string archFlavor = pathComponents[pathComponents.Length - 1];
            string opteeCompilerFlavor;
            if (archFlavor != "export-ta_arm32")
            {
                opteeCompilerFlavor = "aarch64-linux-gnu-";
            }
            else
            {
                if (IsHardwareFloatSupported(folder))
                {
                    opteeCompilerFlavor = "arm-linux-gnueabihf-";
                }
                else
                {
                    opteeCompilerFlavor = "arm-linux-gnueabi-";
                }
            }
            replacementsDictionary.Add("$OpteeCompilerFlavor$", opteeCompilerFlavor);

            return true;
        }

        private bool SetEnclaveName(Dictionary<string, string> replacementsDictionary)
        {
            try
            {
                string safeitemname;
                replacementsDictionary.TryGetValue("$safeitemname$", out safeitemname);

                // Extract enclave name.
                if (safeitemname.EndsWith("_host") && (safeitemname.Length > 5))
                {
                    string enclavename = safeitemname.Substring(0, safeitemname.Length - 5);

                    // Add $enclavename$.
                    replacementsDictionary.Add("$enclavename$", enclavename);
                }

                // Try to get enclave guid from the enclave project.
                string enclaveguid = "FILL THIS IN";
                string makFileName = Path.Combine(EdlLocation, "optee", "linux_gcc.mak");
                foreach (string line in File.ReadLines(makFileName))
                {
                    int index = line.IndexOf("BINARY=");
                    if (index >= 0)
                    {
                        enclaveguid = line.Substring(index + 7).Trim();
                        break;
                    }
                }
                replacementsDictionary.Add("$enclaveguid$", enclaveguid);

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
                // Get the $guid1$ value that has already been generated, and
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
