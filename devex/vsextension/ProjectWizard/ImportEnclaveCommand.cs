// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
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
using EnvDTE80;
using System.IO;
using Microsoft.VisualStudio.Threading;

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
            ThreadHelper.ThrowIfNotOnUIThread();
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
            ThreadHelper.ThrowIfNotOnUIThread();
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
            ThreadHelper.ThrowIfNotOnUIThread();
            ProjectItem folder = FindProjectItem(project, name);
            if (folder == null)
            {
                folder = project.ProjectItems.AddFolder(name, EnvDTE.Constants.vsProjectItemKindVirtualFolder);
            }
            return folder;
        }

        /// <summary>
        /// Create a new configuration by copying an existing one
        /// </summary>
        /// <param name="project">Project to add the configuration to</param>
        /// <param name="newName">Name of new configuration</param>
        /// <param name="baseName">Name of configuration to copy from</param>
        private void AddConfiguration(Project project, string newName, string baseName)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // Add the configuration to the project.
            var dte = Package.GetGlobalService(typeof(SDTE)) as DTE;
            project.ConfigurationManager.AddConfigurationRow(newName, baseName, true);

            // Set the VcpkgConfiguration property of each new configuration to the baseName.
            var vcProject = project.Object as VCProject;
            foreach (var config in vcProject.Configurations)
            {
                string name = config.Name;
                if (name.Contains(newName))
                {
                    var config3 = config as VCConfiguration3;
                    config3.SetPropertyValue("Configuration", true, "VcpkgConfiguration", baseName);
                }
            }

            // Now set the solution's configuration to use the relevant project's configurations.
            foreach (SolutionConfiguration2 solutionConfig in dte.Solution.SolutionBuild.SolutionConfigurations)
            {
                if (solutionConfig.Name != newName)
                {
                    continue;
                }
                foreach (SolutionContext context in solutionConfig.SolutionContexts)
                {
                    // Select newName if it exists for this project, else baseName.
                    try
                    {
                        context.ConfigurationName = baseName;
                    }
                    catch (Exception)
                    {
                    }

                    try
                    {
                        context.ConfigurationName = newName;
                    }
                    catch (Exception)
                    {
                    }
                }
            }
        }

        private bool HavePlatform(Project project, string baseName)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            var arr = project.ConfigurationManager.PlatformNames as Array;
            foreach (string p in arr)
            {
                if (p == baseName)
                {
                    return true;
                }
            }
            return false;
        }

        private void AddPlatform(Project project, string newName, string baseName)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            // Add the platform to the project.
            var dte = Package.GetGlobalService(typeof(SDTE)) as DTE;
            project.ConfigurationManager.AddPlatform(newName, baseName, true);

            // Now set the solution platform to build the project's platform.
            foreach (SolutionConfiguration2 solutionConfig in dte.Solution.SolutionBuild.SolutionConfigurations)
            {
                if (solutionConfig.PlatformName != newName)
                {
                    continue;
                }
                foreach (SolutionContext context in solutionConfig.SolutionContexts)
                {
                    if (context.ProjectName == project.UniqueName)
                    {
                        context.ConfigurationName = context.ConfigurationName + "|" + newName;
                        context.ShouldBuild = true;
                    }
                }
            }
        }

        /// <summary>
        /// Add a file to an existing project.
        /// </summary>
        /// <param name="templateName">Template name</param>
        /// <param name="language">Programming language</param>
        /// <param name="destinationFileName">Destination file name</param>
        private void AddProjectItem(string templateName, string language, string destinationFileName)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            try
            {
                var dte = Package.GetGlobalService(typeof(SDTE)) as DTE;
                var solution = dte.Solution as EnvDTE80.Solution2;
                Project project = GetActiveProject(dte);

                string templateFileName = solution.GetProjectItemTemplate(templateName, language);
                ProjectItem item = project.ProjectItems.AddFromTemplate(templateFileName, destinationFileName);
                var file = item.Object as VCFile;
                foreach (var config in file.FileConfigurations)
                {
                    var tool = config.Tool;
                    tool.UsePrecompiledHeader = 0; // none
                }
            }
            catch (Exception)
            {

            }
        }
        
        Project FindProject(Solution solution, string projectFolder)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            var projects = solution.Projects;
            foreach (var p in projects)
            {
                var project = p as Project;
                var vcProject = project.Object as VCProject;
                if (vcProject != null)
                {
                    string folder = Path.GetDirectoryName(vcProject.ProjectDirectory);
                    if (projectFolder == folder)
                    {
                        return project;
                    }
                }
            }

            return null;
        }

        private bool IsEnclave(Project project)
        {
            ThreadHelper.ThrowIfNotOnUIThread();

            var vcProject = project.Object as VCProject;
            VCConfiguration vcConfig = vcProject.ActiveConfiguration;
            string oeType = vcConfig.Evaluate("$(OEType)");
            return (oeType == "Enclave");
        }

        /// <summary>
        /// This function is the callback used to execute the command when the menu item is clicked.
        /// See the constructor to see how the menu item is associated with this function using
        /// OleMenuCommandService service and MenuCommand class.
        /// </summary>
        /// <param name="sender">Event sender</param>
        /// <param name="e">Event args</param>
        private async void Execute(object sender, EventArgs e)
        {
            await ThreadHelper.JoinableTaskFactory.SwitchToMainThreadAsync();

            var dte = Package.GetGlobalService(typeof(SDTE)) as DTE;
            Project project = GetActiveProject(dte);
            var vcProject = project.Object as VCProject;

            if (IsEnclave(project))
            {
                MessageBox.Show("The project to import into must not be another enclave.");
                return;
            }

            var filePath = string.Empty;
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                // InitialDirectory must be an absolute, not relative, path.
                openFileDialog.InitialDirectory = Path.GetDirectoryName(dte.Solution.FileName);
                openFileDialog.Filter = "EDL files (*.EDL)|*.edl";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    Cursor.Current = Cursors.WaitCursor;

                    // Get the path of specified file.
                    filePath = openFileDialog.FileName;
                    WizardImplementation.EdlLocation = Path.GetDirectoryName(filePath);

                    // Extract base name of enclave.
                    string baseName = System.IO.Path.GetFileNameWithoutExtension(filePath);

                    // Add list of generated files to the project.
                    ProjectItem generatedFilesFolder = FindOrAddVirtualFolder(project, "Generated Files");
                    try
                    {
                        generatedFilesFolder.ProjectItems.AddFromFile(baseName + "_u.h");
                        generatedFilesFolder.ProjectItems.AddFromFile(baseName + "_args.h");
                        ProjectItem ucItem = generatedFilesFolder.ProjectItems.AddFromFile(baseName + "_u.c");
                        var ucFile = ucItem.Object as VCFile;
                        foreach (var config in ucFile.FileConfigurations)
                        {
                            var tool = config.Tool;
                            tool.UsePrecompiledHeader = 0; // none
                        }
                    } catch (Exception)
                    {
                        // File couldn't be added, it may already exist.
                    }

                    // Add nuget package to project.
                    // See https://stackoverflow.com/questions/41803738/how-to-programmatically-install-a-nuget-package/41895490#41895490
                    // and more particularly https://docs.microsoft.com/en-us/nuget/visual-studio-extensibility/nuget-api-in-visual-studio
                    var packageVersions = new Dictionary<string, string>() { { "open-enclave-cross", "0.11.0-rc1-cbe4dedc-2" } };
                    var componentModel = (IComponentModel)(await this.ServiceProvider.GetServiceAsync(typeof(SComponentModel)));
                    var packageInstaller = componentModel.GetService<IVsPackageInstaller2>();
                    packageInstaller.InstallPackagesFromVSExtensionRepository(
                        "OpenEnclaveVisualStudioExtension-1", // extensionId
                        false, // isPreUnzipped
                        false, // skipAssemblyReferences
                        false, // ignoreDependencies
                        project,
                        packageVersions);

                    // Add the EDL file to the project.
                    // We need to do this after adding the OE extension so the EdlItem type can be found.
                    ProjectItem sourceFilesFolder = FindOrAddVirtualFolder(project, "Source Files");
                    try
                    {
                        ProjectItem edlItem = sourceFilesFolder.ProjectItems.AddFromFile(filePath);
                    }
                    catch (Exception)
                    {
                        // File couldn't be added, it may already exist.
                    }

                    bool isWindows = (vcProject.keyword != "Linux");

                    foreach (VCConfiguration config in vcProject.Configurations)
                    {
                        var config3 = config as VCConfiguration3;
                        string name = config.Name;

                        if (name.Contains("ARM"))
                        {
                            var clRule = config.Rules.Item("CL") as IVCRulePropertyStorage;
                            string value = clRule.GetUnevaluatedPropertyValue("PreprocessorDefinitions");
                            clRule.SetPropertyValue("PreprocessorDefinitions", "_ARM_;" + value);
                        }

                        if (!isWindows && name.Contains("Debug"))
                        {
                            // GCC has no preprocessor define for debug mode, but the generated host file
                            // expects _DEBUG, so set it here.
                            var clRule = config.Rules.Item("CL") as IVCRulePropertyStorage;
                            string value = clRule.GetUnevaluatedPropertyValue("PreprocessorDefinitions");
                            clRule.SetPropertyValue("PreprocessorDefinitions", "_DEBUG;" + value);
                        }

                        if (isWindows)
                        {
                            // Change OutDir to $(SolutionDir)bin\$(Platform)\$(Configuration)\
                            // so it's the same as the enclave.
                            config.OutputDirectory = "$(SolutionDir)bin\\$(Platform)\\$(Configuration)\\";
                        }
                        else
                        {
                            // Add a post-build event to copy the enclave binary to the existing OutDir.
                            string cmd = "cp $(RemoteRootDir)/" + baseName + "/bin/$(Platform)/$(Configuration)/" + baseName + ".signed $(RemoteOutDir)" + baseName;
                            var cbeRule = config.Rules.Item("ConfigurationBuildEvents") as IVCRulePropertyStorage;
                            cbeRule.SetPropertyValue("RemotePostBuildCommand", cmd);
                            cbeRule.SetPropertyValue("RemotePostBuildMessage", "Copying enclave binary");
                        }

                        if (name.Contains("OPTEE") || name.Contains("ARM") || isWindows)
                        {
                            // Set the debugger's working directory to where the binary is placed.
                            VCDebugSettings debugging = config.DebugSettings;
                            debugging.WorkingDirectory = "$(OutDir)";
                            continue;
                        }

                        // Linux SGX remote compilation.
                        // Configure gdb like the oe-gdb script does.
                        var gdbRule = config.Rules.Item("LinuxDebugger");
                        if (gdbRule != null)
                        {
                            // Configure GDB debugger settings.
                            string gdbEnvironmentSettings = "export PYTHONPATH=/opt/openenclave/lib/openenclave/debugger/gdb-sgx-plugin;export LD_PRELOAD=/opt/openenclave/lib/openenclave/debugger/liboe_ptrace.so";
                            gdbRule.SetPropertyValue("PreLaunchCommand", gdbEnvironmentSettings);
                            gdbRule.SetPropertyValue("AdditionalDebuggerCommands", "directory /opt/openenclave/lib/openenclave/debugger/gdb-sgx-plugin;source /opt/openenclave/lib/openenclave/debugger/gdb-sgx-plugin/gdb_sgx_plugin.py;set environment LD_PRELOAD;add-auto-load-safe-path /usr/lib");
                        }
                    }

                    // Add a host code item to the project.
                    AddProjectItem("OEHostItem", "VC", baseName + "_host.c");

                    // Add a reference to the enclave project if it's in the same solution.
                    Project enclaveProject = FindProject(dte.Solution, WizardImplementation.EdlLocation);
                    if (enclaveProject != null)
                    {
                        try
                        {
                            var vcProjectReference = vcProject.AddProjectReference(enclaveProject) as VCProjectReference;
                            vcProjectReference.LinkLibraryDependency = false;
                        } catch (Exception)
                        {
                            // Reference couldn't be added, it may already exist.
                        }
                    }

                    Cursor.Current = Cursors.Default;
                }
            }
        }
    }
}
