// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

"use strict";
import * as fse from "fs-extra";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import * as zlib from "zlib";

import { AcrManager } from "../common/acrManager";
import { Constants } from "../common/constants";
import { RequirementsChecker } from "../common/requirementsChecker";
import { TelemetryClient } from "../common/telemetryClient";
import { Utility } from "../common/utility";

type ProgressUpdater = vscode.Progress<{ message?: string; increment?: number }>;
type PartialProgressOptions = Partial<vscode.ProgressOptions>;

interface IUserProgressOptions extends PartialProgressOptions {
    isUserInitiated?: boolean;
    cancellationToken?: vscode.CancellationToken;
}
const defaultProgressOptions: vscode.ProgressOptions = {
    location: vscode.ProgressLocation.Notification,
    title: Constants.openEnclaveDisplayName,
};
const userProgressOptionsDefaults: IUserProgressOptions = {
    ...defaultProgressOptions,
    isUserInitiated: true,
    cancellationToken: undefined,
};

export class OpenEnclaveManager {

    private _context: vscode.ExtensionContext;

    constructor(context: vscode.ExtensionContext) {
        this._context = context;
    }

    public async createOpenEnclaveSolution(outputChannel: vscode.OutputChannel): Promise<void> {
        return this.promiseWithProgress(async (progress, resolve, reject) => {
            return this.internalCreateOpenEnclaveSolution(outputChannel, progress)
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    public async checkRequirements(outputChannel: vscode.OutputChannel): Promise<void> {
        return this.promiseWithProgress(async (progress, resolve, reject) => {
            return RequirementsChecker.checkRequirements(true, true)
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    private getEmbeddedDevKitTarballPath(): string {
        return this._context.asAbsolutePath(path.join(Constants.assetsFolder, Constants.devKitFolder, Constants.devKitTarball));
    }

    private async internalCreateOpenEnclaveSolution(outputChannel: vscode.OutputChannel, progress: ProgressUpdater): Promise<void> {
        return new Promise(async (resolve, reject) => {
            // Prompt user for new Solution path
            const parentPath: string | undefined = await this.getSolutionParentFolder();
            if (parentPath === undefined) {
                reject();
            } else {
                try {
                    // Populate new solution folder with Open Enclave code
                    const openEnclaveFolder = await this.populateOpenEnclaveSolution(parentPath, outputChannel, progress);
                    resolve();

                    // Open new solution in VSCode
                    await vscode.commands.executeCommand("vscode.openFolder", vscode.Uri.file(openEnclaveFolder), false);
                } catch (error) {
                    reject(error);
                }
            }
        });
    }

    private async populateOpenEnclaveSolution(parentFolder: string, outputChannel: vscode.OutputChannel, progress: ProgressUpdater): Promise<string> {
        return new Promise(async (resolve, reject) => {

            try {
                // Determine what style of project to create (standalone | edge-container)
                //    Note: this is only a choice on Linux, otherwise, only edge-container is available.
                let createEdgeSolution = true;
                let dockerRepo: string | undefined;
                if (os.platform() === "linux") {
                    const oeProjectStyle = await Utility.showQuickPick([Constants.standaloneProjectType, Constants.edgeProjectType], Constants.selectProjectType);
                    createEdgeSolution = (oeProjectStyle === Constants.edgeProjectType);
                }

                TelemetryClient.sendEvent(`msiot-vscode-openenclave.newSolution.${createEdgeSolution ? "edge" : "standalone"}`);

                // Prompt user for solution name
                const openEnclaveName: string | undefined =
                    await this.inputSolutionName(parentFolder, (createEdgeSolution) ? Constants.edgeSolutionNameDefault : Constants.standaloneSolutionNameDefault);
                if (openEnclaveName === undefined) {
                    reject();
                    return "";
                }

                // Prompt user for docker repo if needed
                if (createEdgeSolution) {
                    const dftValue: string = `localhost:5000/${openEnclaveName.toLowerCase()}`;
                    dockerRepo = await Utility.showInputBox(Constants.repositoryPattern, Constants.providerDockerRepository, undefined, dftValue);
                }

                // Get Solution Path
                const openEnclaveFolder: string = path.join(parentFolder, openEnclaveName);
                await fse.mkdirsSync(openEnclaveFolder);

                // Create new UUID for solution
                const uuidv4 = require("uuid/v4");
                const uuid: string = uuidv4();
                // Create shared/non-Shared build and sdk folders
                const devkitFolder = path.join(openEnclaveFolder, Constants.devKitFolder);
                const sdkFolder = path.join(openEnclaveFolder, Constants.thirdPartyFolder, Constants.openEnclaveSdkName);
                const buildFolder = path.join(openEnclaveFolder, Constants.standaloneBuildFolder);
                // Create map of template replacements (i.e. [[XXX]] => yyy)
                const replacementMap: Map<string, string> =
                    this.setupTemplateReplacementMap(openEnclaveFolder, openEnclaveName, sdkFolder, devkitFolder, buildFolder, uuid, dockerRepo);

                const enclaveFolder = (createEdgeSolution) ? path.join(openEnclaveFolder, Constants.edgeModulesFolder, openEnclaveName) : openEnclaveFolder;
                await fse.mkdirsSync(enclaveFolder);

                // Create user files with template replacements made
                this.progressAndOutput("Creating base files", progress, outputChannel);
                // Put base files in place
                const baseTemplateSolutionPath = this._context.asAbsolutePath(path.join(Constants.assetsFolder, Constants.baseSolutionTemplateFolder));
                await Utility.copyTemplateFiles(baseTemplateSolutionPath, enclaveFolder, null, replacementMap);
                this.progressAndOutput("Base files created", progress, outputChannel);
                if (createEdgeSolution) {
                    this.progressAndOutput("Creating edge files", progress, outputChannel);
                    // Put edge files in place
                    const edgeTemplateSolutionPath = this._context.asAbsolutePath(path.join(Constants.assetsFolder, Constants.edgeSolutionTemplateFolder));
                    await Utility.copyTemplateFiles(edgeTemplateSolutionPath, openEnclaveFolder, null, replacementMap);
                } else {
                    this.progressAndOutput("Creating standalone files", progress, outputChannel);
                    // Put standalone files in place
                    const standaloneTemplateSolutionPath = this._context.asAbsolutePath(path.join(Constants.assetsFolder, Constants.standaloneSolutionTemplateFolder));
                    await Utility.copyTemplateFiles(standaloneTemplateSolutionPath, openEnclaveFolder, null, replacementMap);
                }

                if (createEdgeSolution) {
                    if (dockerRepo) {
                        this.progressAndOutput("Updating deployment template", progress, outputChannel);
                        const address = Utility.getRegistryAddress(dockerRepo);
                        const addressKey = Utility.getAddressKey(address);
                        const lowerCase = address.toLowerCase();
                        if (lowerCase !== "mcr.microsoft.com" && lowerCase !== "localhost" && !lowerCase.startsWith("localhost:")) {
                            await this.writeRegistryCredEnv(address, path.join(openEnclaveFolder, ".env"), `${addressKey}_USERNAME`, `${addressKey}_PASSWORD`);
                            await this.internalUpdateDeploymentTemplate(openEnclaveFolder, address, addressKey, `${addressKey}_USERNAME`, `${addressKey}_PASSWORD`);
                        }
                    }
                } else {
                    // Ensure that the build folders are created for the standalone project
                    this.progressAndOutput("Creating build folders", progress, outputChannel);
                    await fse.mkdirsSync(path.join(openEnclaveFolder, Constants.standaloneBuildFolder, "sgx"));
                    await fse.mkdirsSync(path.join(openEnclaveFolder, Constants.standaloneBuildFolder, "vexpress-qemu_armv8a"));
                    await fse.mkdirsSync(path.join(openEnclaveFolder, Constants.standaloneBuildFolder, "ls-ls1012grapeboard"));
                }

                // Ensure that the devkit is present on the system
                const sharedDevkitLocation = path.join(this._context.globalStoragePath, Constants.DevKitVersion, Constants.devKitFolder);
                if (!fse.existsSync(sharedDevkitLocation)) {
                    const embeddedDevkitPath = this.getEmbeddedDevKitTarballPath();
                    this.progressAndOutput("Expanding platform devkit (this is infrequent)", progress, outputChannel);
                    await this.internalExpandDevkit(fse.createReadStream(embeddedDevkitPath), sharedDevkitLocation, progress, outputChannel);
                }
                // Ensure that the devkit is present in the project
                this.progressAndOutput("Adding devkit to solution", progress, outputChannel);
                await this.internalMakeCopyOrLink(sharedDevkitLocation, path.join(enclaveFolder, Constants.devKitFolder), !createEdgeSolution);

                // Success!
                this.progressAndOutput("Created Open Enclave solution", progress, outputChannel);
                resolve(openEnclaveFolder);

            } catch (error) {
                TelemetryClient.sendEvent(`msiot-vscode-openenclave.newSolution.Failure`, {error: (error) ? error.message : "unknown"});
                this.progressAndOutput("Failed to create new Open Enclave solution", progress, outputChannel);
                reject(error);
            }
        });
    }

    private async writeRegistryCredEnv(address: string, envFile: string, usernameEnv: string, passwordEnv: string, debugUsernameEnv?: string, debugPasswordEnv?: string): Promise<void> {
        if (!usernameEnv) {
            return;
        }

        if (address.endsWith(".azurecr.io")) {
            await this.populateAcrCredential(address, envFile, usernameEnv, passwordEnv, debugUsernameEnv, debugPasswordEnv);
        } else {
            await this.populateStaticEnv(envFile, usernameEnv, passwordEnv, debugUsernameEnv, debugPasswordEnv);
        }
    }

    private async populateStaticEnv(envFile: string, usernameEnv: string, passwordEnv: string, debugUsernameEnv?: string, debugPasswordEnv?: string): Promise<void> {
        let envContent = `\n${usernameEnv}=\n${passwordEnv}=\n`;
        if (debugUsernameEnv && debugUsernameEnv !== usernameEnv) {
            envContent = `\n${envContent}${debugUsernameEnv}=\n${debugPasswordEnv}=\n`;
        }
        await fse.ensureFile(envFile);
        await fse.appendFile(envFile, envContent, { encoding: "utf8" });
        this.askEditEnv(envFile);
    }

    private async populateAcrCredential(address: string, envFile: string, usernameEnv: string, passwordEnv: string, debugUsernameEnv?: string, debugPasswordEnv?: string): Promise<void> {
        const acrManager = new AcrManager();
        let cred;
        try {
            cred = await acrManager.getAcrRegistryCredential(address);
        } catch (err) {
            // tslint:disable-next-line:no-console
            console.error(err);
        }
        if (cred && cred.username !== undefined) {
            let envContent = `\n${usernameEnv}=${cred.username}\n${passwordEnv}=${cred.password}\n`;
            if (debugUsernameEnv && debugUsernameEnv !== usernameEnv) {
                envContent = `\n${envContent}${debugUsernameEnv}=${cred.username}\n${debugPasswordEnv}=${cred.password}\n`;
            }
            await fse.ensureFile(envFile);
            await fse.appendFile(envFile, envContent, { encoding: "utf8" });
            vscode.window.showInformationMessage(Constants.acrEnvSet);
        } else {
            await this.populateStaticEnv(envFile, usernameEnv, passwordEnv, debugUsernameEnv, debugPasswordEnv);
        }
    }

    private async askEditEnv(envFile: string): Promise<void> {
        const yesOption = "Yes";
        const option = await vscode.window.showInformationMessage(Constants.setRegistryEnvNotification, yesOption);
        if (option === yesOption) {
            await fse.ensureFile(envFile);
            await vscode.window.showTextDocument(vscode.Uri.file(envFile));
        }
    }

    private async internalUpdateDeploymentTemplate(openEnclaveFolder: string, address: string, addressKey: string, usernameEnv: string, passwordEnv: string): Promise<void> {
        return new Promise<void>(async (resolve, reject) => {
            const lowerCase = address.toLowerCase();
            if (lowerCase === "mcr.microsoft.com" || lowerCase === "localhost" || lowerCase.startsWith("localhost:")) {
                resolve();
            } else {
                try {

                    const filesAndDirs = await fse.readdir(openEnclaveFolder);
                    await Promise.all(
                        filesAndDirs.map(async (name) => {
                            const templateFile = path.join(openEnclaveFolder, name);
                            const stat: fse.Stats = await fse.stat(templateFile);
                            if (stat.isFile()) {
                                const matches = name.match(new RegExp(Constants.configDeploymentFilePattern));
                                if (matches && matches.length !== 0) {
                                    const templateContents = await fse.readFile(templateFile, "utf8");
                                    const templateJson = JSON.parse(templateContents);
                                    const runtimeSettings = templateJson.modulesContent.$edgeAgent["properties.desired"].runtime.settings;
                                    const newRegistry = `{
                                        "username": "$${usernameEnv}",
                                        "password": "$${passwordEnv}",
                                        "address": "${address}"
                                    }`;
                                    runtimeSettings.registryCredentials = {};
                                    runtimeSettings.registryCredentials[addressKey] = JSON.parse(newRegistry);
                                    await fse.writeFile(templateFile, JSON.stringify(templateJson, null, 2), { encoding: "utf8" });
                                }
                            }
                        }),
                    );

                    resolve();
                } catch (error) {
                    reject(error);
                }
            }
        });
    }

    private internalMakeCopyOrLink(sharedLocation: string, localLocation: string, useSymLink: boolean): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            try {
                if (useSymLink) {
                    fse.symlinkSync(sharedLocation, localLocation);
                } else {
                    fse.copySync(sharedLocation, localLocation);
                }
                resolve();
            } catch (error) {
                reject(error);
            }
        });
    }

    private internalMove(originalLocation: string, newLocation: string): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            try {
                fse.moveSync(originalLocation, newLocation);
                resolve();
            } catch (error) {
                reject(error);
            }
        });
    }

    private async internalDownloadDevKitFromBlobStorage(progress: ProgressUpdater, outputChannel: vscode.OutputChannel): Promise<void> {
        return new Promise(async (resolve, reject) => {
            // Ensure that DevKit blob information is available
            const account = Constants.DevKitBlobAccount;
            const containerName = Constants.DevKitBlobContainerName;
            const blobName = Constants.DevKitBlobName;
            if (account === "" || containerName === "" || blobName === "") {
                reject("missing DevKit source");
            } else {
                const storageAccountUri = "https://" + account + ".blob.core.windows.net";

                // Download devkit from Azure Blob
                this.progressAndOutput("Downloading devkit", progress, outputChannel);
                const tmp = require("tmp");
                return tmp.file({prefix: Constants.devKitFolder, postfix: ".tmp"}, async (err: Error, tempFilePath: string, fd: any, cleanupCallback: any) => {
                    if (err) {
                        reject(err);
                    } else {
                        const storage = require("azure-storage");
                        const blobService = storage.createBlobServiceAnonymous(storageAccountUri);
                        blobService.getBlobToLocalFile(containerName, blobName, tempFilePath, async (blobErr: Error) => {
                            if (blobErr) {
                                reject(blobErr);
                            } else {
                                // Expand downloaded devkit tarball to local path
                                this.progressAndOutput("Expanding devkit", progress, outputChannel);
                                await this.internalExpandDevkit(fse.createReadStream(tempFilePath), null, progress, outputChannel);
                                // Remove temp file
                                await cleanupCallback();
                                resolve();
                            }
                        });
                    }
                });
            }
        });
    }

    private async internalExpandDevkit(devKitStream: NodeJS.ReadableStream, incomingWorkspaceFolder: string | null, progress: ProgressUpdater, outputChannel: vscode.OutputChannel): Promise<void> {
        return new Promise(async (resolve, reject) => {
            const workspaceFolders = vscode.workspace.workspaceFolders;
            const workspaceFolder: string | undefined = (incomingWorkspaceFolder !== null) ?
                incomingWorkspaceFolder :
                (workspaceFolders && workspaceFolders.length > 0) ?
                    path.join(workspaceFolders[0].uri.fsPath, Constants.devKitFolder) :
                    undefined;

            if (workspaceFolder !== undefined) {
                fse.pathExists(workspaceFolder, (pathExistsErr: Error, exists: boolean) => {
                    if (pathExistsErr) {
                        reject(pathExistsErr);
                    } else if (exists) {
                        // If sdkDestination exists, it must be emptied and deleted.
                        return this.clearFolderAndThen(workspaceFolder, resolve, reject, progress, outputChannel, () => {
                            // Folder has been deleted, download SDK from git
                            return this.expandTarGzStream(devKitStream, workspaceFolder, "Expanding shared devkit", progress, outputChannel)
                                .then(() => {
                                    // Signal success
                                    resolve();
                                })
                                .catch((gitErr) => {
                                    // Signal git failure
                                    reject(gitErr);
                                });
                        });
                    } else {
                        // If folder does not exist, download SDK from git
                        return this.expandTarGzStream(devKitStream, workspaceFolder, "Expanding shared devkit", progress, outputChannel)
                            .then(() => {
                                // Signal success
                                resolve();
                            })
                            .catch((gitErr) => {
                                // Signal git failure
                                reject(gitErr);
                            });
                    }});
            }
        });
    }

    private async expandTarGzStream(devKitStream: NodeJS.ReadableStream, localFilePath: string, progressPrefix: string, progress: ProgressUpdater, outputChannel: vscode.OutputChannel): Promise<void> {
        return new Promise(async (resolve, reject) => {
            this.progressAndOutput(`${progressPrefix}`, progress, outputChannel);
            fse.mkdirsSync(localFilePath);

            // Pipe: DevKit Stream => Zlib unizp => tar.extract
            const tar = require("tar");
            return devKitStream
                    .on("error", (err: Error) => {
                        this.progressAndOutput(`${progressPrefix} failed`, progress, outputChannel);
                        reject(err);
                    })
                    .pipe(zlib.createGunzip())
                    .on("error", (err: Error) => {
                        this.progressAndOutput(`${progressPrefix} failed`, progress, outputChannel);
                        reject(err);
                    })
                    .pipe(tar.extract({ cwd: localFilePath, strip: 0 }))
                    .on("close", () => {
                        this.progressAndOutput(`${progressPrefix} finished`, progress, outputChannel);
                        resolve();
                    })
                    .on("error", (err: Error) => {
                        this.progressAndOutput(`${progressPrefix} failed`, progress, outputChannel);
                        reject(err);
                    });
        });
    }

    private createUuidPart(uuid: string, start: number, end: number): string {
        const uuidPart = uuid.substring(start, end);
        return "0x" + uuidPart;
    }

    private setupTemplateReplacementMap(
        solutionFolder: string,
        solutionName: string,
        sdkFolder: string,
        devkitFolder: string,
        buildFolder: string,
        uuid: string,
        dockerRepo: string | undefined): Map<string, string> {

        // Create map of template replacements (i.e. [[XXX]] => yyy)
        const replacementMap: Map<string, string> = new Map<string, string>();
        if (uuid.length !== 36 ||
            uuid.charAt(8) !== "-" ||
            uuid.charAt(13) !== "-" ||
            uuid.charAt(18) !== "-" ||
            uuid.charAt(23) !== "-") {
            throw new Error("invalid uuid: " + uuid);
        }

        // Add UUID and UUID parts to template replacement map
        replacementMap.set("[[generated-uuid]]", uuid);
        replacementMap.set("[[generated-uuid-part-1]]", this.createUuidPart(uuid, 0, 8));
        replacementMap.set("[[generated-uuid-part-2]]", this.createUuidPart(uuid, 9, 13));
        replacementMap.set("[[generated-uuid-part-3]]", this.createUuidPart(uuid, 14, 18));
        replacementMap.set("[[generated-uuid-part-4-a]]", this.createUuidPart(uuid, 19, 21));
        replacementMap.set("[[generated-uuid-part-4-b]]", this.createUuidPart(uuid, 21, 23));
        replacementMap.set("[[generated-uuid-part-5-a]]", this.createUuidPart(uuid, 24, 26));
        replacementMap.set("[[generated-uuid-part-5-b]]", this.createUuidPart(uuid, 26, 28));
        replacementMap.set("[[generated-uuid-part-5-c]]", this.createUuidPart(uuid, 28, 30));
        replacementMap.set("[[generated-uuid-part-5-d]]", this.createUuidPart(uuid, 30, 32));
        replacementMap.set("[[generated-uuid-part-5-e]]", this.createUuidPart(uuid, 32, 34));
        replacementMap.set("[[generated-uuid-part-5-f]]", this.createUuidPart(uuid, 34, 36));
        // Add solution name to template replacement map
        replacementMap.set("[[project-name]]", solutionName);
        // Add devkit path to template replacement map
        const normalizedDevkitPath = devkitFolder.replace(new RegExp("\\\\", "g"), "/");
        replacementMap.set("[[devkit-folder]]", normalizedDevkitPath);
        // Add solution path to template replacement map
        const normalizedSolutionPath = solutionFolder.replace(new RegExp("\\\\", "g"), "/");
        replacementMap.set("[[solution-folder]]", normalizedSolutionPath);
        // Add sdk path to template replacement map
        const normalizedSdkPath = sdkFolder.replace(new RegExp("\\\\", "g"), "/");
        replacementMap.set("[[sdk-folder]]", normalizedSdkPath);
        // Add build path to template replacement map
        const normalizedBuildPath = buildFolder.replace(new RegExp("\\\\", "g"), "/");
        replacementMap.set("[[build-folder]]", normalizedBuildPath);
        // Add settings file name to template replacement map
        replacementMap.set("[[settings]]", "settings");

        // If docker repo is provided, add it to map
        if (dockerRepo) {
            replacementMap.set("[[docker-repo]]", dockerRepo);

            const dockerRepoAddress = Utility.getRegistryAddress(dockerRepo);
            replacementMap.set("[[docker-repo-address]]", dockerRepoAddress);
        }

        return replacementMap;
    }

    private async getSolutionParentFolder(): Promise<string | undefined> {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        const defaultFolder: vscode.Uri | undefined = workspaceFolders && workspaceFolders.length > 0 ? workspaceFolders[0].uri : undefined;
        const selectedUri: vscode.Uri[] | undefined = await vscode.window.showOpenDialog({
            defaultUri: defaultFolder,
            openLabel: Constants.selectFolderLabel,
            canSelectFiles: false,
            canSelectFolders: true,
            canSelectMany: false,
        });

        if (!selectedUri || selectedUri.length === 0) {
            return undefined;
        }

        return selectedUri[0].fsPath;
    }

    private async getDevKitTarball(): Promise<string | undefined> {
        const embeddedDevkitPath = this.getEmbeddedDevKitTarballPath();
        const selectedUri: vscode.Uri[] | undefined = await vscode.window.showOpenDialog({
            defaultUri: vscode.Uri.file(embeddedDevkitPath),
            openLabel: Constants.selectDevKitLabel,
            canSelectFiles: true,
            canSelectFolders: false,
            canSelectMany: false,
            filters: { "DevKit tarball": ["tar.gz"] },
        });

        if (!selectedUri || selectedUri.length === 0) {
            return undefined;
        }

        return selectedUri[0].fsPath;
    }

    private async inputSolutionName(parentPath: string, defaultName: string): Promise<string> {
        const validateFunc = async (name: string): Promise<string> => {
            return await this.validateSolutionName(name, parentPath) as string;
        };
        return await Utility.showInputBox(Constants.solutionName,
            Constants.solutionNamePrompt,
            validateFunc, defaultName);
    }

    private async validateSolutionName(name: string, parentPath?: string): Promise<string | undefined> {
        if (!name || name.trim() === "") {
            return "The name could not be empty";
        }
        if (!/^[0-9a-zA-Z_]+$/.test(name)) {
            return "Solution name must only contain characters: 0-9, a-z, A-Z, and _";
        }
        if (parentPath) {
            const folderPath = path.join(parentPath, name);
            if (await fse.pathExists(folderPath)) {
                return `${name} already exists under ${parentPath}`;
            }
        }
        return undefined;
    }

    private async clearFolderAndThen(folder: string, resolve: any, reject: any, progress: ProgressUpdater, outputChannel: vscode.OutputChannel, callback: () => Promise<any>) {
        const clearFolderMessage = "Clearing folder: " + folder;
        this.progressAndOutput(clearFolderMessage, progress, outputChannel);
        fse.emptyDir(
            folder,
            (emptyDirErr) => {
                if (emptyDirErr) {
                    // Empty failed, call reject
                    this.progressAndOutput("Emptying folder failed.", progress, outputChannel);
                    reject(emptyDirErr);
                } else {
                    // Folder has been emptied, now remove it
                    const removingFolderMessage = "Removing folder: " + folder;
                    this.progressAndOutput(removingFolderMessage, progress, outputChannel);
                    fse.rmdir(
                        folder,
                        (rmdirErr) => {
                            if (rmdirErr) {
                                this.progressAndOutput("Removing folder failed.", progress, outputChannel);
                                reject(rmdirErr);
                            } else {
                                // Folder has been deleted, execute callback
                                callback().then(() => {
                                    // Signal success
                                    resolve();
                                }).catch((callbackErr) => {
                                    // Signal callback failure
                                    reject(callbackErr);
                                });
                            }
                        });
                }
            });

    }

    private async promiseWithProgress(callback: (progress: ProgressUpdater, resolve: any, reject: any) => Promise<any>): Promise<void> {

        const progressOptions: IUserProgressOptions = userProgressOptionsDefaults;
        const options: IUserProgressOptions = {
            ...userProgressOptionsDefaults,
            ...progressOptions,
        };

        return await vscode.window.withProgress(
            options as vscode.ProgressOptions,
            async (progress: ProgressUpdater) => {

            return new Promise<void>(async (resolve, reject) => {

                return await callback(progress, resolve, reject);

            });
        });
    }

    private progress(message: string, progress: ProgressUpdater) {
        this.progressAndOutput(message, progress, undefined);
    }

    private progressAndOutput(message: string, progress: ProgressUpdater, outputChannel: vscode.OutputChannel | undefined) {
        progress.report({ message });
        if (outputChannel) {
            outputChannel.show();
            outputChannel.appendLine(message);
        }
    }
}
