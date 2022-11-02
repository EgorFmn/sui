// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { encrypt, decrypt } from '_shared/cryptography/keystore';
import {
    mnemonicToEntropy,
    validateMnemonics,
    entropyToMnemonic,
} from '_shared/utils/bip39';

export type StoredData = string | { v: number; data: string };

/**
 * Holds the mnemonic of the wallet and provides functionality to create/encrypt/decrypt it.
 */
export class Vault {
    readonly #version = 1;
    public readonly mnemonic: string;
    readonly #entropy: Uint8Array;

    public static async from(
        password: string,
        data: StoredData,
        onMigrateCallback?: (vault: Vault) => Promise<void>
    ) {
        let mnemonic: string | null = null;
        let doMigrate = false;
        if (typeof data === 'string') {
            mnemonic = (await decrypt(password, data)).toString();
            doMigrate = true;
        } else if (data.v === 1) {
            const entropy = new Uint8Array(await decrypt(password, data.data));
            mnemonic = entropyToMnemonic(entropy);
        } else {
            throw new Error(
                "Unknown data, provided data can't be used to create a Vault"
            );
        }
        if (!validateMnemonics(mnemonic)) {
            throw new Error('Invalid mnemonic');
        }
        const vault = new Vault(mnemonic);
        if (doMigrate && typeof onMigrateCallback === 'function') {
            await onMigrateCallback(vault);
        }
        return vault;
    }

    constructor(mnemonic: string) {
        this.mnemonic = mnemonic;
        this.#entropy = mnemonicToEntropy(mnemonic);
    }

    public async encrypt(password: string) {
        return {
            v: this.#version,
            data: await encrypt(password, Buffer.from(this.#entropy)),
        };
    }
}
