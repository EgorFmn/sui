// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import cl from 'clsx';

import Longtext from '../../components/longtext/Longtext';

import styles from './SendReceiveView.module.css';

type TxAddress = {
    timestamp_ms?: number;
    sender: string;
    recipient?: string[];
};
//TODO: Add date format function
function SendRecieveView({ data }: { data: TxAddress }) {
    return (
        <div className={styles.txaddress} data-testid="transaction-sender">
            <div className={styles.txaddressheader}>
                <h3 className={styles.label}>
                    Sender {data.recipient?.length ? '& Recipients' : ''}{' '}
                    {data.timestamp_ms && (
                        <span>{new Date(data.timestamp_ms).toUTCString()}</span>
                    )}
                </h3>
            </div>
            <div
                className={cl([
                    styles.txaddresssender,
                    data.recipient?.length ? styles.recipient : '',
                ])}
            >
                <Longtext text={data.sender} category="addresses" isLink />
                {data.recipient && (
                    <ul className={styles.txrecipents}>
                        {data.recipient.map((add: string, idx: number) => (
                            <li key={idx}>
                                <Longtext
                                    text={add}
                                    category="addresses"
                                    isLink
                                    alttext={add}
                                />
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </div>
    );
}

export default SendRecieveView;
