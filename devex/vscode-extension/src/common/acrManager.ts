// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

"use strict";
import { ContainerRegistryManagementClient } from "azure-arm-containerregistry";
import { Registry, RegistryListCredentialsResult } from "azure-arm-containerregistry/lib/models";
import { Registries } from "azure-arm-containerregistry/lib/operations";
import * as vscode from "vscode";
import { Utility } from "../common/utility";
import { AzureAccount } from "../typings/azure-account.api";
import { AcrRegistryQuickPickItem } from "./models/acrRegistryQuickPickItem";

export class AcrManager {
    private readonly azureAccount: AzureAccount;

    constructor() {
        this.azureAccount = vscode.extensions.getExtension<AzureAccount>("ms-vscode.azure-account")!.exports;
    }

    public async getAcrRegistryCredential(address: string): Promise<{ username: string | undefined, password: string | undefined }> {
        let username: string | undefined;
        let password: string | undefined;

        if (await this.azureAccount.waitForLogin()) {
            const registriesItems = await this.loadAcrRegistryItems();
            for (const registryItem of registriesItems) {
                const registry = registryItem.registry;
                if (registry.loginServer === address && registry.adminUserEnabled) {
                    const azureSubscription = registryItem.azureSubscription;
                    const registryName = registry.name;
                    const resourceGroup = Utility.getResourceGroupFromId(registry.id);
                    const client = new ContainerRegistryManagementClient(
                        azureSubscription.session.credentials,
                        azureSubscription.subscription.subscriptionId!,
                    );
                    if (resourceGroup && registryName) {
                        const creds: RegistryListCredentialsResult = await client.registries.listCredentials(resourceGroup, registryName);
                        if (creds.username && creds.passwords && creds.passwords[0].value) {
                            username = creds.username;
                            password = creds.passwords[0].value;
                            break;
                        }
                    }
                }
            }
        }

        return { username, password };
    }

    private async loadAcrRegistryItems(): Promise<AcrRegistryQuickPickItem[]> {
        try {
            await this.azureAccount.waitForFilters();
            const registryPromises: Array<Promise<AcrRegistryQuickPickItem[]>> = [];
            for (const azureSubscription of this.azureAccount.filters) {
                const client: Registries = new ContainerRegistryManagementClient(
                    azureSubscription.session.credentials,
                    azureSubscription.subscription.subscriptionId!,
                ).registries;

                registryPromises.push(
                    Utility.listAzureResources<Registry>(client.list(), client.listNext)
                        .then((registries: Registry[]) => registries.map((registry: Registry) => {
                            return new AcrRegistryQuickPickItem(registry, azureSubscription);
                        })),
                );
            }

            const registryItems: AcrRegistryQuickPickItem[] = await Utility.awaitPromiseArray<AcrRegistryQuickPickItem>(registryPromises, "Azure Container Registry");
            return registryItems;
        } catch (error) {
            error.message = `Error fetching registry list: ${error.message}`;
            throw error;
        }
    }
}
