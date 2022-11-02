// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import passworder from '@metamask/browser-passworder';

export async function encrypt(
    password: string,
    // TODO: is Buffer the best way to pass secrets to passworder?
    // Passworder uses JSON.stringify and converts the result of that to
    // Buffer to use it for the encryption
    secrets: Buffer
): Promise<string> {
    return passworder.encrypt(password, secrets);
}

export async function decrypt(
    password: string,
    ciphertext: string
): Promise<Buffer> {
    // using encrypt above we always encrypt a Buffer. passworder though uses JSON.stringify and the result of that
    // is being encrypted. So when we decrypt the actual result is an object of the stringified object,
    // something like { data: [12,12312,312,...], type: 'Buffer', }.
    // using Buffer.from to actually create a Buffer.
    return Buffer.from(await passworder.decrypt(password, ciphertext));
}
