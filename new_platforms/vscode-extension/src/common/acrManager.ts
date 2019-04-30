// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

"use strict";
import { ContainerRegistryManagementClient } from "azure-arm-containerregistry";
import { Registry, RegistryListCredentialsResult } from "azure-arm-containerregistry/lib/models";
import { Registries } from "azure-arm-containerregistry/lib/operations";
import * as vscode from "vscode";
import { Constants } from "../common/constants";
import { Utility } from "../common/utility";
import { AzureAccount } from "../typings/azure-account.api";
import { AcrRegistryQuickPickItem } from "./models/acrRegistryQuickPickItem";

export class AcrManager {
    private readonly azureAccount: AzureAccount;
    // private acrRefreshToken: string;

    constructor() {
        this.azureAccount = vscode.extensions.getExtension<AzureAccount>("ms-vscode.azure-account")!.exports;
    }

    // public async selectAcrImage(): Promise<string> {
    //     const acrRegistryItem: AcrRegistryQuickPickItem = await this.selectAcrRegistry();
    //     if (acrRegistryItem === undefined) {
    //         throw new UserCancelledError();
    //     }

    //     const registryUrl: string = acrRegistryItem.registry.loginServer;

    //     const acrRepoItem: vscode.QuickPickItem = await this.selectAcrRepo(registryUrl, acrRegistryItem.azureSubscription.session);
    //     if (acrRepoItem === undefined) {
    //         throw new UserCancelledError();
    //     }

    //     const acrTagItem: vscode.QuickPickItem = await this.selectAcrTag(registryUrl, acrRepoItem.label);
    //     if (acrTagItem === undefined) {
    //         throw new UserCancelledError();
    //     }

    //     return acrTagItem.description;
    // }

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

    // private async selectAcrRepo(registryUrl: string, session: AzureSession): Promise<vscode.QuickPickItem> {
    //     const acrRepoItem: vscode.QuickPickItem = await vscode.window.showQuickPick(this.loadAcrRepoItems(registryUrl, session), { placeHolder: "Select Repository", ignoreFocusOut: true });
    //     return acrRepoItem;
    // }

    // private async loadAcrRepoItems(registryUrl: string, session: AzureSession): Promise<vscode.QuickPickItem[]> {
    //     try {
    //         const { aadAccessToken, aadRefreshToken } = await Utility.acquireAadToken(session);
    //         this.acrRefreshToken = await this.acquireAcrRefreshToken(registryUrl, session.tenantId, aadRefreshToken, aadAccessToken);
    //         const acrAccessToken = await this.acquireAcrAccessToken(registryUrl, "registry:catalog:*", this.acrRefreshToken);

    //         const catalogResponse = await request.get(`https://${registryUrl}/v2/_catalog`, {
    //             auth: {
    //                 bearer: acrAccessToken,
    //             },
    //         });

    //         const repoItems: vscode.QuickPickItem[] = [];
    //         const repos = JSON.parse(catalogResponse).repositories;

    //         if (!repos) {
    //             const error: any = new Error("There is no repository in the registry.");
    //             error.statusCode = 404;
    //             throw error;
    //         }

    //         repos.map((repo) => {
    //             repoItems.push({
    //                 label: repo,
    //                 description: `${registryUrl}/${repo}`,
    //             });
    //         });
    //         repoItems.sort((a, b) => a.label.localeCompare(b.label));
    //         return repoItems;
    //     } catch (error) {
    //         error.message = `Error fetching repository list: ${error.message}`;

    //         if (error.statusCode === 404) {
    //             error.message = `Please make sure that there is at least one repository in the registry. ${error.message}`;
    //         }

    //         throw error;
    //     }
    // }

    // private async acquireAcrRefreshToken(registryUrl: string, tenantId: string, aadRefreshToken: string, aadAccessToken: string): Promise<string> {
    //     const acrRefreshTokenResponse = await request.post(`https://${registryUrl}/oauth2/exchange`, {
    //         form: {
    //             grant_type: "access_token_refresh_token",
    //             service: registryUrl,
    //             tenant: tenantId,
    //             refresh_token: aadRefreshToken,
    //             access_token: aadAccessToken,
    //         },
    //     });
    //     return JSON.parse(acrRefreshTokenResponse).refresh_token;
    // }

    // private async acquireAcrAccessToken(registryUrl: string, scope: string, acrRefreshToken: string) {
    //     const acrAccessTokenResponse = await request.post(`https://${registryUrl}/oauth2/token`, {
    //         form: {
    //             grant_type: "refresh_token",
    //             service: registryUrl,
    //             scope,
    //             refresh_token: acrRefreshToken,
    //         },
    //     });
    //     return JSON.parse(acrAccessTokenResponse).access_token;
    // }

    // private async selectAcrTag(registryUrl: string, repo: string): Promise<vscode.QuickPickItem> {
    //     const tag: vscode.QuickPickItem = await vscode.window.showQuickPick(this.loadAcrTagItems(registryUrl, repo), { placeHolder: "Select Tag", ignoreFocusOut: true });
    //     return tag;
    // }

    // private async loadAcrTagItems(registryUrl: string, repo: string): Promise<vscode.QuickPickItem[]> {
    //     try {
    //         const acrAccessToken = await this.acquireAcrAccessToken(registryUrl, `repository:${repo}:pull`, this.acrRefreshToken);

    //         const tagsResponse = await request.get(`https://${registryUrl}/v2/${repo}/tags/list`, {
    //             auth: {
    //                 bearer: acrAccessToken,
    //             },
    //         });

    //         const tagItems: vscode.QuickPickItem[] = [];
    //         const tags = JSON.parse(tagsResponse).tags;
    //         tags.map((tag) => {
    //             tagItems.push({
    //                 label: tag,
    //                 description: `${registryUrl}/${repo}:${tag}`,
    //             });
    //         });
    //         tagItems.sort((a, b) => a.label.localeCompare(b.label));
    //         return tagItems;
    //     } catch (error) {
    //         error.message = `Error fetching tag list: ${error.message}`;
    //         throw error;
    //     }
    // }
}
