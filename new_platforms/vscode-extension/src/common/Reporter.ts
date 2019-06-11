// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

"use strict";
import * as vscode from "vscode";
import TelemetryReporter from "vscode-extension-telemetry";
import { Constants } from "./constants";

export var reporter: TelemetryReporter;

export class Reporter extends vscode.Disposable {
    constructor(ctx: vscode.ExtensionContext) {
        super(() => reporter.dispose());
        const packageInfo = getPackageInfo(ctx);
        if (packageInfo !== undefined) {
            reporter = new TelemetryReporter(packageInfo.name, packageInfo.version, packageInfo.aiKey);
        }
    }
}

interface IPackageInfo {
    name: string;
    version: string;
    aiKey: string;
}

function getPackageInfo(context: vscode.ExtensionContext): IPackageInfo | undefined {
    const extensionPackage = require(context.asAbsolutePath("./package.json"));
    if (extensionPackage) {
        return { name: extensionPackage.name, version: extensionPackage.version, aiKey: extensionPackage.aiKey };
    }
    return;
}