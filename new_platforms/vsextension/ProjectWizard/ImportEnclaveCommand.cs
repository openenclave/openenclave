using System;
using System.ComponentModel.Design;
using System.Windows.Forms;
using Microsoft.VisualStudio.Shell;
using Microsoft.VisualStudio.Shell.Interop;
using EnvDTE;
using Task = System.Threading.Tasks.Task;
using NuGet.VisualStudio;
using System.Collections.Generic;
using Microsoft.VisualStudio.ComponentModelHost;
using Microsoft.VisualStudio.VCProjectEngine;

namespace OpenEnclaveSDK
{
    /// <summary>
    /// Command handler
    /// </summary>
    internal sealed class ImportEnclaveCommand
    {
        /// <summary>
        /// Command ID.
        /// </summary>
        public const int CommandId = 0x0100;

        /// <summary>
        /// Command menu group (command set GUID).
        /// </summary>
        public static readonly Guid CommandSet = new Guid("6818d8e0-d425-4d85-a296-32e1a4b63fcc");

        /// <summary>
        /// VS Package that provides this command, not null.
        /// </summary>
        private readonly AsyncPackage package;

        /// <summary>
        /// Initializes a new instance of the <see cref="ImportEnclaveCommand"/> class.
        /// Adds our command handlers for menu (commands must exist in the command table file)
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        /// <param name="commandService">Command service to add command to, not null.</param>
        private ImportEnclaveCommand(AsyncPackage package, OleMenuCommandService commandService)
        {
            this.package = package ?? throw new ArgumentNullException(nameof(package));
            commandService = commandService ?? throw new ArgumentNullException(nameof(commandService));

            var menuCommandID = new CommandID(CommandSet, CommandId);
            var menuItem = new MenuCommand(this.Execute, menuCommandID);
            commandService.AddCommand(menuItem);
        }

        /// <summary>
        /// Gets the instance of the command.
        /// </summary>
        public static ImportEnclaveCommand Instance
        {
            get;
            private set;
        }

        /// <summary>
        /// Gets the service provider from the owner package.
        /// </summary>
        private Microsoft.VisualStudio.Shell.IAsyncServiceProvider ServiceProvider
        {
            get
            {
                return this.package;
            }
        }

        /// <summary>
        /// Initializes the singleton instance of the command.
        /// </summary>
        /// <param name="package">Owner package, not null.</param>
        public static async Task InitializeAsync(AsyncPackage package)
        {
            // Switch to the main thread - the call to AddCommand in ImportEnclaveCommand's constructor requires
            // the UI thread.
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync(package.DisposalToken);

            var commandService = await package.GetServiceAsync((typeof(IMenuCommandService))) as OleMenuCommandService;
            Instance = new ImportEnclaveCommand(package, commandService);
        }

        static Project GetActiveProject(DTE dte)
        {
            Project activeProject = null;

            var activeSolutionProjects = dte.ActiveSolutionProjects as Array;
            if (activeSolutionProjects != null && activeSolutionProjects.Length > 0)
            {
                activeProject = activeSolutionProjects.GetValue(0) as Project;
            }

            return activeProject;
        }

        static ProjectItem FindProjectItem(Project project, string name)
        {
            foreach (ProjectItem item in project.ProjectItems)
            {
                if (item.Name == name)
                {
                    return item;
                }
            }
            return null;
        }

        private ProjectItem FindOrAddVirtualFolder(Project project, string name)
        {
            ProjectItem folder = FindProjectItem(project, name);
            if (folder == null)
            {
                folder = project.ProjectItems.AddFolder(name, EnvDTE.Constants.vsProjectItemKindVirtualFolder);
            }
            return folder;
        }

        /// <summary>
        /// This function is the callback used to execute the command when the menu item is clicked.
        /// See the constructor to see how the menu item is associated with this function using
        /// OleMenuCommandService service and MenuCommand class.
        /// </summary>
        /// <param name="sender">Event sender.</param>
        /// <param name="e">Event args.</param>
        private async void Execute(object sender, EventArgs e)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            var dte = Package.GetGlobalService(typeof(SDTE)) as DTE;
            Project project = GetActiveProject(dte);

            var filePath = string.Empty;
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.InitialDirectory = ".";
                openFileDialog.Filter = "EDL files (*.EDL)|*.edl";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    // Get the path of specified file.
                    filePath = openFileDialog.FileName;

                    // Extract base name.
                    string baseName = System.IO.Path.GetFileNameWithoutExtension(filePath);

                    // Add list of generated files to the project.
                    ProjectItem generatedFilesFolder = FindOrAddVirtualFolder(project, "Generated Files");
                    generatedFilesFolder.ProjectItems.AddFromFile(baseName + "_u.h");
                    ProjectItem ucItem = generatedFilesFolder.ProjectItems.AddFromFile(baseName + "_u.c");
                    var ucFile = ucItem.Object as VCFile;
                    foreach (var config in ucFile.FileConfigurations)
                    {
                        var tool = config.Tool;
                        tool.UsePrecompiledHeader = 0; // none
                    }

                    // Add the EDL file to the project.
                    ProjectItem sourceFilesFolder = FindOrAddVirtualFolder(project, "Source Files");
                    ProjectItem edlItem = sourceFilesFolder.ProjectItems.AddFromFile(filePath);
                    var edlFile = edlItem.Object as VCFile;
                    foreach (var config in edlFile.FileConfigurations)
                    {
                        var tool = config.Tool;
                        tool.CommandLine = "\"$(OEEdger8rPath)\" --untrusted \"%(FullPath)\" --search-path \"$(OEIncludePath)\"";
                        tool.Description = "Creating untrusted proxy/bridge routines";
                        tool.Outputs = "%(Filename)_t.h;%(Filename)_t.c;%(Outputs)";
                    }

                    // Add nuget package to project.
                    // See https://stackoverflow.com/questions/41803738/how-to-programmatically-install-a-nuget-package/41895490#41895490
                    // and more particularly https://docs.microsoft.com/en-us/nuget/visual-studio-extensibility/nuget-api-in-visual-studio
                    var packageVersions = new Dictionary<string, string>() { { "openenclave", "0.2.0-CI-20190122-200026" } };
                    var componentModel = (IComponentModel)(await this.ServiceProvider.GetServiceAsync(typeof(SComponentModel)));
                    var packageInstaller = componentModel.GetService<IVsPackageInstaller2>();
                    packageInstaller.InstallPackagesFromVSExtensionRepository(
                        "OpenEnclaveVisualStudioExtension-1", // extensionId
                        false, // isPreUnzipped
                        false, // skipAssemblyReferences
                        false, // ignoreDependencies
                        project,
                        packageVersions);

                    // Add any configurations/platforms to the project.
                    project.ConfigurationManager.AddConfigurationRow("OPTEE-Simulation-Debug", "Debug", true);
                    project.ConfigurationManager.AddConfigurationRow("SGX-Simulation-Debug", "Debug", true);
                    project.ConfigurationManager.AddPlatform("ARM", "Win32", true);

                    // Set the debugger.
                    var vcProject = project.Object as VCProject;
                    foreach (var config in vcProject.Configurations)
                    {
                        string name = config.Name;
                        if (name.Contains("ARM"))
                        {
                            var clRule = config.Rules.Item("CL") as IVCRulePropertyStorage;
                            string value = clRule.GetUnevaluatedPropertyValue("PreprocessorDefinitions");
                            clRule.SetPropertyValue("PreprocessorDefinitions", "_ARM_;" + value);
                        }
                        if (name.Contains("OPTEE") || name.Contains("ARM"))
                        {
                            continue;
                        }
                        var generalRule = config.Rules.Item("DebuggerGeneralProperties") as IVCRulePropertyStorage;
                        generalRule.SetPropertyValue("DebuggerFlavor", "SGXDebugLauncher");

                        var sgxRule = config.Rules.Item("SGXDebugLauncher") as IVCRulePropertyStorage;
                        sgxRule.SetPropertyValue("IntelSGXDebuggerWorkingDirectory", "$(OutDir)");
                    }
                }
            }
        }
    }
}
