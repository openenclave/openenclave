// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
"use strict";
import { ChildProcess, spawn } from "child_process";
import * as vscode from "vscode";

export class GitHelper {

    public static getRepo(gitRepo: string, gitBranch: string, destination: string, outputChannel: vscode.OutputChannel): Promise<void> {
        const command = "git";
        const args = [
            "clone",
            "--recursive",
            "--branch",
            gitBranch.startsWith("#") ? gitBranch.substr(1) : gitBranch,
            gitRepo,
            `\"${destination}\"`,
        ];

        outputChannel.show();
        outputChannel.appendLine(`Executing: ${command} ${args.join(" ")}`);

        return this.spawnProcess(command, args, outputChannel);
    }

    private static spawnProcess(command: string, args: string[], outputChannel: vscode.OutputChannel): Promise<void> {
        return new Promise((resolve, reject) => {
            let stderr: string = "";

            const p: ChildProcess = spawn(command, args, {shell: true});
            p.stdout.on("data", (data: string | Buffer): void => {
                const dataStr = data.toString();
                outputChannel.append(dataStr);
            });
            p.stderr.on("data", (data: string | Buffer) => {
                const dataStr = data.toString();
                stderr = stderr.concat(dataStr);
                outputChannel.append(dataStr);
            });
            p.on("error", (err: Error) => {
                reject(new Error(`${err.toString()}. Detail: ${stderr}`));
            });
            p.on("exit", (code: number, signal: string) => {
                if (code !== 0) {
                    reject (new Error((`Command failed with exit code ${code}. Detail: ${stderr}`)));
                } else {
                    resolve();
                }
            });
        });
    }
}
