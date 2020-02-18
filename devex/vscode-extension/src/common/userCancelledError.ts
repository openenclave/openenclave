// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

export class UserCancelledError extends Error {
    constructor() {
        super("Operation cancelled.");
    }
}