// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

export class UserCancelledError extends Error {
    constructor() {
        super("Operation cancelled.");
    }
}
