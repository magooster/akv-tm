/*
 * Copyright 2020 Ian Cusden.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package net.iaminnovative.tx;

import java.io.IOException;
import java.math.BigInteger;

import org.web3j.protocol.Web3j;
import org.web3j.tx.ChainIdLong;
import org.web3j.tx.response.TransactionReceiptProcessor;

import net.iaminnovative.keyvault.KeyVaultClient;

/**
 * Inspired by
 * https://github.com/web3j/web3j/blob/master/core/src/main/java/org/web3j/tx/FastRawTransactionManager.java
 */
public class KeyVaultFastTransactionManager extends KeyVaultTransactionManager {

    private volatile BigInteger nonce = BigInteger.valueOf(-1);

    public KeyVaultFastTransactionManager(Web3j web3j, KeyVaultClient client, long chainId) {
        super(web3j, client, chainId);
    }

    public KeyVaultFastTransactionManager(Web3j web3j, KeyVaultClient client) {
        super(web3j, client);
    }

    public KeyVaultFastTransactionManager(
            Web3j web3j,
            KeyVaultClient client,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(web3j, client, ChainIdLong.NONE, transactionReceiptProcessor);
    }

    public KeyVaultFastTransactionManager(
            Web3j web3j,
            KeyVaultClient client,
            byte chainId,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(web3j, client, chainId, transactionReceiptProcessor);
    }

    @Override
    protected synchronized BigInteger getNonce() throws IOException {
        if (nonce.signum() == -1) {
            // obtain lock
            nonce = super.getNonce();
        } else {
            nonce = nonce.add(BigInteger.ONE);
        }
        return nonce;
    }

    public BigInteger getCurrentNonce() {
        return nonce;
    }

    public synchronized void resetNonce() throws IOException {
        nonce = super.getNonce();
    }

    public synchronized void setNonce(BigInteger value) {
        nonce = value;
    }
}
