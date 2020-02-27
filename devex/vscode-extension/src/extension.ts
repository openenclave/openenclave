// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from "vscode";
import { Constants } from "./common/constants";
import { ErrorData } from "./common/ErrorData";
import { RequirementsChecker } from "./common/requirementsChecker";
import { TelemetryClient } from "./common/telemetryClient";
import { UserCancelledError } from "./common/userCancelledError";
import { OpenEnclaveManager } from "./openenclave/openEnclaveManager";

// this method is called when your extension is activated
// your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

    TelemetryClient.sendEvent("extensionActivated: " + Constants.ExtensionId);
    const outputChannel: vscode.OutputChannel = vscode.window.createOutputChannel(Constants.openEnclaveDisplayName);
    const openEnclaveManager = new OpenEnclaveManager(context);

    RequirementsChecker.checkRequirements(false, false);

    // Add Open Solution command
    initCommandAsync(context, outputChannel,
        "msiot-vscode-openenclave.newSolution",
        (): Promise<void> => {
            return openEnclaveManager.createOpenEnclaveSolution(outputChannel);
        });

    // Add Check System Requirements command
    initCommandAsync(context, outputChannel,
        "msiot-vscode-openenclave.checkSystemRequirements",
        (): Promise<void> => {
            return openEnclaveManager.checkRequirements(outputChannel);
        });
}

function initCommandAsync(
    context: vscode.ExtensionContext,
    outputChannel: vscode.OutputChannel,
    commandId: string, callback: (...args: any[]) => Promise<any>): void {

        context.subscriptions.push(vscode.commands.registerCommand(commandId, async (...args: any[]) => {
            const start: number = Date.now();
            let errorData: ErrorData | undefined;
            const properties: { [key: string]: string; } = {};
            properties.result = "Succeeded";
            outputChannel.appendLine(`${commandId}: `);
            try {
                return await callback(...args);
            } catch (error) {
                if (error instanceof UserCancelledError) {
                    properties.result = "Cancelled";
                    outputChannel.appendLine(Constants.userCancelled);
                } else if (error) {
                    properties.result = "Failed";
                    errorData = new ErrorData(error);
                    outputChannel.appendLine(`Error: ${errorData.message}`);
                    vscode.window.showErrorMessage(errorData.message);
                }
            } finally {
                const end: number = Date.now();
                properties.duration = ((end - start) / 1000).toString();
                if (errorData) {
                    properties.error = errorData.errorType;
                    properties.errorMessage = errorData.message;
                }
            }
        }));
}

// this method is called when your extension is deactivated
export function deactivate() {}
