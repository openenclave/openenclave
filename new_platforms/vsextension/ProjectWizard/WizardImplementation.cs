using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TemplateWizard;
using System.Windows.Forms;
using EnvDTE;

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

        public void RunStarted(
            object automationObject,
            Dictionary<string, string> replacementsDictionary,
            WizardRunKind runKind,
            object[] customParams)
        {
            try
            {
                string guid1;
                replacementsDictionary.TryGetValue("$guid1$", out guid1);

                /* Add $guid1struct$ */
                Guid guid1binary = Guid.Parse(guid1);
                string guid1struct = guid1binary.ToString("X");
                replacementsDictionary.Add("$guid1struct$", guid1struct);
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
