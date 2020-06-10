// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import { ChildProcess, spawn } from "child_process";
import * as os from "os";
import * as vscode from "vscode";
import { Configuration } from "./configuration";
import { Constants } from "./constants";

export class RequirementsChecker {

    public static async checkRequirements(force: boolean, showSuccess: boolean) {

        const systemConfigurationPassed = Configuration.getConfiguration().get<string>("systemRequirementsPassed");
        if (!force && systemConfigurationPassed && systemConfigurationPassed === Constants.requirementsVersion) {
            return;
        }

        const promises: Array<Promise<any>> = [];
        const warnings: string[] = [];
        if (os.platform() === "linux") {
            promises.push(this.validateTool("aarch64-linux-gnu-gcc", ["--version"])
                .catch(async () => {
                    warnings.push("Unable to locate GCC (aarch64-linux-gnu-gcc).");
                }));
            promises.push(this.validateTool("aarch64-linux-gnu-g++", ["--version"])
                .catch(async () => {
                    warnings.push("Unable to locate G++ (aarch64-linux-gnu-g++).");
                }));
            promises.push(this.validateTool("gdb-multiarch", ["--version"])
                .catch(async () => {
                    warnings.push("Unable to locate GDB (gdb-multiarch).");
                }));
            promises.push(this.validateTool("python", ["--version"])
                .catch(async () => {
                    warnings.push("Unable to locate PYTHON.");
                }));
            promises.push(this.validateTool("cmake", ["--version"])
                .then(async (output) => {
                    const versionLine = output.split("\n").filter((line) => line.indexOf("cmake version") !== -1);
                    if (versionLine && versionLine.length > 0) {
                        const versionMatches = versionLine[0].match(/^cmake version ([0-9]+)\.([0-9]+)\.([0-9]+)$/);
                        if (versionMatches && versionMatches.length === 4) {
                            const major = parseInt(versionMatches[1], 10);
                            const minor = parseInt(versionMatches[2], 10);
                            if (major < 3 || (major === 3 && minor < 12)) {
                                warnings.push(`Incorrect CMAKE found (${major}.${minor}).  Version 3.12.0 or higher is required.`);
                            }
                        }
                    }
                })
                .catch(async () => {
                    warnings.push("Unable to locate CMAKE 3.12 or higher.");
                }));
        } else if (os.platform() === "win32") {
            promises.push(this.validateTool("git", ["config", "--get", "core.longpaths"])
                .then(async (output) => {
                    if (!output || !(/^true/.test(output.trim().toLowerCase()))) {
                        warnings.push(`Enable long paths for GIT.`);
                    }
                })
                .catch(async () => {
                    warnings.push(`Enable long paths for GIT.`);
                }));
        }
        promises.push(this.checkDocker()
            .then(async (results) => {
                results.forEach((result) => warnings.push(result));
            }));
        promises.push(this.validateTool("git", ["--version"])
            .catch(async () => {
                warnings.push("Unable to locate GIT.");
            }));
        await Promise.all(promises)
            .then(async () => {
                if (warnings.length !== 0) {
                    await this.showWarning(warnings.join("  "));
                } else {
                    // Update global settings to reflect that this system meets this version's requirements
                    Configuration.setGlobalConfigurationProperty("systemRequirementsPassed", Constants.requirementsVersion);
                    if (showSuccess) {
                        vscode.window.showInformationMessage("System meets requirements.");
                    }
                }
            });
    }

    private static async showWarning(message: string) {
        const requirementsLink = "https://marketplace.visualstudio.com/items?itemName=ms-iot.msiot-vscode-openenclave";
        const learnMore: vscode.MessageItem = { title: "Learn more" };

        if (await vscode.window.showWarningMessage(`Some requirements are not found.  ${message}  Click Learn more button to see requirements.` , ...[learnMore]) === learnMore) {
            await vscode.commands.executeCommand("vscode.open", vscode.Uri.parse(requirementsLink));
        }
    }

    private static async checkDocker(): Promise<string[]> {
        const warnings: string[] = [];

        // Check for docker installation
        await Promise.all([
            this.validateTool("docker", ["--version"])
                .catch(async () => {
                    warnings.push("Unable to locate DOCKER.");
                })
        ]);

        // If docker is found, check for cross-build capability on linux
        if (warnings.length === 0 && os.platform() === "linux") {
            const promises: Array<Promise<any>> = [];
            promises.push(this.validateTool("docker", ["run amd64/ubuntu:xenial"])
                .catch(async () => {
                    warnings.push("Unable to run amd64 container, enable docker cross-building.");
                }));
            promises.push(this.validateTool("docker", ["run arm32v7/ubuntu:xenial"])
                .catch(async () => {
                    warnings.push("Unable to run arm32v7 container, enable docker cross-building.");
                }));
            promises.push(this.validateTool("docker", ["run aarch64/ubuntu:xenial"])
                .catch(async () => {
                    warnings.push("Unable to run aarch64 container, enable docker cross-building.");
                }));
            await Promise.all(promises);
        }

        return warnings;
    }

    private static validateTool(command: string, args: string[]): Promise<string> {

        return new Promise(async (resolve, reject) => {

            let stderr: string = "";
            let stdOutput: string = "";

            const p: ChildProcess = spawn(command, args, {shell: true});
            p.stdout.on("data", (data: string | Buffer): void => {
                const dataStr = data.toString();
                stdOutput = stdOutput.concat(dataStr);
            });
            p.stderr.on("data", (data: string | Buffer) => {
                const dataStr = data.toString();
                stderr = stderr.concat(dataStr);
            });
            p.on("error", (err: Error) => {
                reject(new Error(`${err.toString()}. Detail: ${stderr}`));
            });
            p.on("exit", (code: number) => {
                if (code !== 0) {
                    reject (new Error((`Command failed with exit code ${code}. Detail: ${stderr}`)));
                } else {
                    resolve(stdOutput);
                }
            });
        });
    }
}
