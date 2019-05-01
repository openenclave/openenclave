// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
"use strict";
import * as fse from "fs-extra";
import * as path from "path";
import * as vscode from "vscode";

import { Constants } from "./constants";
import { GitClone } from "./modifiedDownloadGitRepo";

type ProgressUpdater = vscode.Progress<{ message?: string; increment?: number }>;
interface IGitSubmodule {
    path: string;
    url: string;
    branch?: string;
}

export class GitHelper {

    public static recursiveCloneFromGit(gitRepo: string, gitBranch: string, destination: string, isSubmodule: boolean, progress: ProgressUpdater): Promise<void> {
        return new Promise(async (resolve, reject) => {
            const gitUrl = gitRepo + gitBranch;
            const progressMessagePrefix = (isSubmodule) ? "Cloning git submodule" : "Cloning git repo";
            progress.report({ message: (progressMessagePrefix + ": " + gitUrl) });
            const downloadUrl = "direct:" + gitUrl;
            return GitHelper.downloadFromDownloadGitRepo(downloadUrl, destination, progressMessagePrefix, progress)
                .then(() => {
                    resolve();
                })
                .catch((err) => {
                    reject(err);
                });
        });
    }

    private static downloadFromDownloadGitRepo(url: string, destination: string, progressPrefix: string, progress: ProgressUpdater) {
        return new Promise(async (resolve, reject) => {
            GitClone.download(url, destination, { clone: true }, (err: any) => {
                if (err) {

                    progress.report({ message: (progressPrefix + " failed.") });
                    reject(err);

                } else {

                    progress.report({ message: (progressPrefix + " succeeded.") });

                    // If there is a .gitsubmodule file, use it to clone submodules
                    const gitsubmoduleFile = path.join(destination, ".gitmodules");
                    if (fse.pathExistsSync(gitsubmoduleFile)) {
                        const gitsubmodules = GitHelper.parseGitModulesFile(gitsubmoduleFile);
                        const promises =
                            gitsubmodules.map(async (submodule: IGitSubmodule) => {
                                const submoduleDestination = path.join(destination, submodule.path);
                                const branch = submodule.branch ? ("#" + submodule.branch) : "";
                                return GitHelper.recursiveCloneFromGit(submodule.url, branch, submoduleDestination, true, progress);
                            });
                        Promise.all(promises)
                            .then(() => {
                                resolve();
                            })
                            .catch((allPromisesErr) => {
                                reject(allPromisesErr);
                            });
                    } else {
                        resolve();
                    }
                }
            });
        });
    }

    private static parseGitModulesFile(gitsubmoduleFile: string): IGitSubmodule[] {
        const submodules = new Array<IGitSubmodule>();
        const submodulesAsText = fse.readFileSync(gitsubmoduleFile, "utf-8");
        submodulesAsText.split("\n").forEach((line) => {
            if (line.startsWith("[submodule")) {
                submodules.push({path: "", url: ""});
            } else {
                const lineData = line.split("=").map((data) => data.trim());
                if (lineData[0] === "path") {
                    submodules[submodules.length - 1].path = lineData[1];
                } else if (lineData[0] === "url") {
                    submodules[submodules.length - 1].url = lineData[1];
                } else if (lineData[0] === "branch") {
                    submodules[submodules.length - 1].branch = lineData[1];
                }
            }
        });
        return submodules;
    }
}
