// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
"use strict";
import { ChildProcess, execSync, ExecSyncOptions, spawn, SpawnOptions } from "child_process";

export class GitHelper {

    public static getRepo(gitRepo: string, gitBranch: string, destination: string): Promise<void> {
        const command = "git";
        const args = [
            "clone",
            "--quiet",
            "--recursive",
            "--branch",
            gitBranch.startsWith("#") ? gitBranch.substr(1) : gitBranch,
            gitRepo,
            destination,
        ];
        return this.spawnProcess(command, args);
    }

    private static spawnProcess(command: string, args: string[]): Promise<void> {
        return new Promise((resolve, reject) => {
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
