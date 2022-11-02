// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { Ed25519Keypair } from '@mysten/sui.js';
import mitt from 'mitt';
import { throttle } from 'throttle-debounce';
import Browser from 'webextension-polyfill';

import { Vault } from './vault';
import { createMessage } from '_messages';
import { isKeyringPayload } from '_payloads/keyring';
import { generateMnemonic } from '_shared/utils/bip39';
import Alarms from '_src/background/Alarms';
import {
    AUTO_LOCK_TIMER_MAX_MINUTES,
    AUTO_LOCK_TIMER_MIN_MINUTES,
    AUTO_LOCK_TIMER_STORAGE_KEY,
} from '_src/shared/constants';

import type { Keypair } from '@mysten/sui.js';
import type { Message } from '_messages';
import type { ErrorPayload } from '_payloads';
import type { KeyringPayload } from '_payloads/keyring';
import type { Connection } from '_src/background/connections/Connection';

type KeyringEvents = {
    lockedStatusUpdate: boolean;
};

const STORAGE_KEY = 'vault';

class Keyring {
    #events = mitt<KeyringEvents>();
    #locked = true;
    #keypair: Keypair | null = null;
    #vault: Vault | null = null;

    // Creates a new mnemonic and saves it to storage encrypted
    // if importedMnemonic is provided it uses that one instead
    public async createMnemonic(password: string, importedMnemonic?: string) {
        if (await this.isWalletInitialized()) {
            throw new Error(
                'Mnemonic already exists, creating a new one will override it. Clear the existing one first.'
            );
        }
        const vault = new Vault(importedMnemonic || generateMnemonic());
        await this.storeEncryptedVault(await vault.encrypt(password));
    }

    public lock() {
        Alarms.clearLockAlarm();
        this.#keypair = null;
        this.#vault = null;
        this.#locked = true;
        this.notifyLockedStatusUpdate(this.#locked);
    }

    public async unlock(password: string) {
        Alarms.setLockAlarm();
        this.#vault = await this.decryptVault(password);
        this.#keypair = Ed25519Keypair.deriveKeypair(this.#vault.mnemonic);
        this.#locked = false;
        this.notifyLockedStatusUpdate(this.#locked);
    }

    public async clearMnemonic() {
        await this.storeEncryptedVault(null);
        this.lock();
    }

    public async isWalletInitialized() {
        return !!(await this.loadMnemonic());
    }

    public get isLocked() {
        return this.#locked;
    }

    public get keypair() {
        return this.#keypair;
    }

    public mnemonic() {
        return this.#vault?.mnemonic;
    }

    // sui address always prefixed with 0x
    public get address() {
        if (this.#keypair) {
            let address = this.#keypair.getPublicKey().toSuiAddress();
            if (!address.startsWith('0x')) {
                address = `0x${address}`;
            }
            return address;
        }
        return null;
    }

    public on = this.#events.on;

    public off = this.#events.off;

    public async handleUiMessage(msg: Message, uiConnection: Connection) {
        const { id, payload } = msg;
        try {
            if (
                isKeyringPayload<'createMnemonic'>(payload, 'createMnemonic') &&
                payload.args !== undefined
            ) {
                const { password, importedMnemonic } = payload.args;
                await this.createMnemonic(password, importedMnemonic);
                await this.unlock(password);
                if (!this.#vault) {
                    throw new Error('Error created mnemonic is empty');
                }
                uiConnection.send(
                    createMessage<KeyringPayload<'createMnemonic'>>(
                        {
                            type: 'keyring',
                            method: 'createMnemonic',
                            return: { mnemonic: this.#vault.mnemonic },
                        },
                        id
                    )
                );
            } else if (
                isKeyringPayload<'getMnemonic'>(payload, 'getMnemonic')
            ) {
                if (this.#locked) {
                    throw new Error('Keyring is locked. Unlock it first.');
                }
                if (!this.#vault?.mnemonic) {
                    throw new Error('Error mnemonic is empty');
                }
                uiConnection.send(
                    createMessage<KeyringPayload<'getMnemonic'>>(
                        {
                            type: 'keyring',
                            method: 'getMnemonic',
                            return: this.#vault.mnemonic,
                        },
                        id
                    )
                );
            } else if (
                isKeyringPayload<'unlock'>(payload, 'unlock') &&
                payload.args
            ) {
                await this.unlock(payload.args.password);
                uiConnection.send(createMessage({ type: 'done' }, id));
            } else if (
                isKeyringPayload<'walletStatusUpdate'>(
                    payload,
                    'walletStatusUpdate'
                )
            ) {
                uiConnection.send(
                    createMessage<KeyringPayload<'walletStatusUpdate'>>(
                        {
                            type: 'keyring',
                            method: 'walletStatusUpdate',
                            return: {
                                isLocked: this.isLocked,
                                isInitialized: await this.isWalletInitialized(),
                                mnemonic: this.#vault?.mnemonic || undefined,
                            },
                        },
                        id
                    )
                );
            } else if (isKeyringPayload<'lock'>(payload, 'lock')) {
                this.lock();
                uiConnection.send(createMessage({ type: 'done' }, id));
            } else if (isKeyringPayload<'clear'>(payload, 'clear')) {
                await this.clearMnemonic();
                uiConnection.send(createMessage({ type: 'done' }, id));
            } else if (
                isKeyringPayload<'appStatusUpdate'>(payload, 'appStatusUpdate')
            ) {
                const appActive = payload.args?.active;
                if (appActive) {
                    this.postponeLock();
                }
            } else if (
                isKeyringPayload<'setLockTimeout'>(payload, 'setLockTimeout')
            ) {
                if (payload.args) {
                    await this.setLockTimeout(payload.args.timeout);
                }
                uiConnection.send(createMessage({ type: 'done' }, id));
            }
        } catch (e) {
            uiConnection.send(
                createMessage<ErrorPayload>(
                    { code: -1, error: true, message: (e as Error).message },
                    id
                )
            );
        }
    }

    // pass null to delete it
    private async storeEncryptedVault(
        encryptedVault: Awaited<ReturnType<Vault['encrypt']>> | null
    ) {
        await Browser.storage.local.set({ [STORAGE_KEY]: encryptedVault });
    }

    private async loadMnemonic() {
        const storedMnemonic = await Browser.storage.local.get({
            [STORAGE_KEY]: null,
        });
        return storedMnemonic[STORAGE_KEY];
    }

    private async decryptVault(password: string) {
        const encryptedVault = await this.loadMnemonic();
        if (!encryptedVault) {
            throw new Error(
                'Mnemonic is not initialized. Create a new one first.'
            );
        }
        return Vault.from(password, encryptedVault, async (aVault) =>
            this.storeEncryptedVault(await aVault.encrypt(password))
        );
    }

    private notifyLockedStatusUpdate(isLocked: boolean) {
        this.#events.emit('lockedStatusUpdate', isLocked);
    }

    private postponeLock = throttle(
        1000,
        async () => {
            if (!this.isLocked) {
                await Alarms.setLockAlarm();
            }
        },
        { noLeading: false }
    );

    private async setLockTimeout(timeout: number) {
        if (
            timeout > AUTO_LOCK_TIMER_MAX_MINUTES ||
            timeout < AUTO_LOCK_TIMER_MIN_MINUTES
        ) {
            return;
        }
        await Browser.storage.local.set({
            [AUTO_LOCK_TIMER_STORAGE_KEY]: timeout,
        });
        if (!this.isLocked) {
            await Alarms.setLockAlarm();
        }
    }
}

export default new Keyring();
