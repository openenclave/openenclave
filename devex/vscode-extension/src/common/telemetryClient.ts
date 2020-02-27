// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

"use strict";
import * as vscode from "vscode";
import TelemetryReporter from "vscode-extension-telemetry";
import { Constants } from "../common/constants";

export class TelemetryClient {

    public static sendEvent(eventName: string, properties?: { [key: string]: string; }): void {

        if (this._client == null || this._client === undefined) {

            const packageExtension = vscode.extensions.getExtension(Constants.ExtensionId);
            if (packageExtension !== undefined) {
                const packageJSON = packageExtension.packageJSON;
                const extensionVersion: string = packageJSON.version;
                // Set up and configure AI: https://docs.microsoft.com/en-us/azure/azure-monitor/learn/nodejs-quick-start
                const aiKey: string = packageJSON.aiKey;
                this._client = new TelemetryReporter(Constants.ExtensionId, extensionVersion, aiKey);
            }
        }

        if (this._client != null && this._client !== undefined) {
            this._client.sendTelemetryEvent(eventName, properties);
        }
    }

    private static _client: TelemetryReporter;
}
