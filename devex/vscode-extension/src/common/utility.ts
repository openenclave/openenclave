// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

"use strict";
import * as fse from "fs-extra";
import * as path from "path";
import * as vscode from "vscode";
import { UserCancelledError } from "./userCancelledError";

export class Utility {
    public static async copyTemplateFiles(baseSrcPath: string, baseTargetPath: string, srcSubPath: string | null, mapObj: Map<string, string>) {

        const srcPath = (srcSubPath === null || srcSubPath === "") ?
            baseSrcPath : path.join(baseSrcPath, srcSubPath);
        const folderContents = await fse.readdir(srcPath);

        const promises = folderContents.map(async (item) => {
            if (fse.statSync(path.join(srcPath, item)).isDirectory()) {
                const itemSubPath = (srcSubPath === null || srcSubPath === "") ?
                    item : path.join(srcSubPath, item);
                await Utility.copyTemplateFiles(baseSrcPath, baseTargetPath, itemSubPath, mapObj);
            } else {
                const targetPath = (srcSubPath === null || srcSubPath === undefined || srcSubPath === "") ?
                    baseTargetPath : path.join(baseTargetPath, srcSubPath);
                await Utility.copyTemplateFile(srcPath, item, targetPath, mapObj);
            }
        });
        await Promise.all(promises);
    }

    public static async copyTemplateFile(srcPath: string, fileName: string, targetPath: string, mapObj: Map<string, string>) {

        const srcFilePath: string = path.join(srcPath, fileName);
        const userFolderPath = Utility.replaceAll(targetPath, mapObj);
        await fse.mkdirs(userFolderPath);

        const srcFileContent: string = await fse.readFile(srcFilePath, "utf8");

        const userFilePath = path.join(
            Utility.replaceAll(targetPath, mapObj),
            Utility.replaceAll(fileName, mapObj))
        .replace(".in", "");
        const userFileContent: string = Utility.replaceAll(srcFileContent, mapObj);
        await fse.writeFile(userFilePath, userFileContent, { encoding: "utf8" });
    }

    public static replaceAll(str: string, mapObj: Map<string, string>, caseInSensitive: boolean = false): string {
        let modifier = "g";
        if (caseInSensitive) {
            modifier = "ig";
        }

        const keys = Array.from(mapObj.keys()).map((k) => k.replace("\[\[", "\\[\\[").replace("\]\]", "\\]\\]"));
        const pattern: RegExp = new RegExp(keys.join("|"), modifier);
        return str.replace(pattern, (matched) => {
            const replacement = mapObj.get(matched);
            if (replacement) {
                return replacement;
            }
            return matched;
        });
    }

    public static async showInputBox(plcHolder: string,
                                     prmpt: string,
                                     validate?: (s: string) => Promise<string> | undefined | null,
                                     defaultValue?: string,
                                     ignFocusOut: boolean = true): Promise<string> {
        const options: vscode.InputBoxOptions = {
            placeHolder: plcHolder,
            prompt: prmpt,
            validateInput: validate,
            ignoreFocusOut: ignFocusOut,
            value: defaultValue,
        };

        const result: string | undefined = await vscode.window.showInputBox(options);
        if (!result) {
            throw new UserCancelledError();
        } else {
            return result;
        }
    }

    public static async showQuickPick(
        items: string[],
        hintText: string,
        ignFocusOut: boolean = true): Promise<string> {

        const options: vscode.QuickPickOptions = {
            placeHolder: hintText,
            ignoreFocusOut: ignFocusOut,
            canPickMany: false,
        };

        const result: string | undefined = await vscode.window.showQuickPick(items, options);
        if (!result) {
            throw new UserCancelledError();
        } else {
            return result;
        }
    }

    public static getRegistryAddress(repositoryName: string) {
        const defaultHostname = "docker.io";
        const legacyDefaultHostname = "index.docker.io";
        const index = repositoryName.indexOf("/");

        let name: string | undefined;
        let hostname: string;
        if (index !== -1) {
            name = (repositoryName.substring(0, index)).toLocaleLowerCase();
        }
        if (name === undefined
            || (name !== "localhost" && (!(name.includes(".") || name.includes(":"))))
        ) {
            hostname = defaultHostname;
        } else {
            hostname = name;
        }

        if (hostname === legacyDefaultHostname) {
            hostname = defaultHostname;
        }

        return hostname;
    }

    public static getResourceGroupFromId(id: string | undefined): string | undefined {
        if (id === undefined || id === "") {
            return undefined;
        }

        const res = id.match(new RegExp("\/resourceGroups\/([^\/]+)(\/)?", "i"));
        if (res === null || res.length < 2) {
            return undefined;
        } else {
            return res[1];
        }
    }

    // The Azure API of listing resources is paginated. This method will follow the links and return all resources
    public static async listAzureResources<T>(
        first: Promise<IAzureResourceListResult<T>>,
        listNext: (nextPageLink: string, options?: { customHeaders?: { [headerName: string]: string; } }) => Promise<IAzureResourceListResult<T>>): Promise<T[]> {

            const all: T[] = [];
            for (let list: any = await first; list !== undefined; list = list.nextLink ? await listNext(list.nextLink) : undefined) {
                all.push(...list);
            }

            return all;
    }

    public static async awaitPromiseArray<T extends vscode.QuickPickItem>(promises: Array<Promise<T[]>>, description: string): Promise<T[]> {
        const items: T[] = ([] as T[]).concat(...(await Promise.all(promises)));
        items.sort((a, b) => a.label.localeCompare(b.label));

        if (items.length === 0) {
            throw new Error(`No ${description} can be found in all selected subscriptions.`);
        }

        return items;
    }

    public static getAddressKey(address: string): string {
        let key = address;
        let index = address.indexOf(".");
        if (index === -1) {
            index = address.indexOf(":");
        }
        if (index !== -1) {
            key = address.substring(0, index);
        }

        return key;
    }
}

interface IAzureResourceListResult<T> extends Array<T> {
    nextLink?: string;
}
