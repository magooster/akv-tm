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
import java.util.Arrays;
import java.util.List;

import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.Sign;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameter;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.core.methods.response.EthCall;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.rlp.RlpEncoder;
import org.web3j.rlp.RlpList;
import org.web3j.rlp.RlpType;
import org.web3j.tx.ChainIdLong;
import org.web3j.tx.TransactionManager;
import org.web3j.tx.exceptions.ContractCallException;
import org.web3j.tx.exceptions.TxHashMismatchException;
import org.web3j.tx.response.TransactionReceiptProcessor;
import org.web3j.utils.Numeric;
import org.web3j.utils.TxHashVerifier;

import net.iaminnovative.keyvault.KeyVaultClient;

/**
 * TransactionManager implementation using Azure Key Vault to create and sign transactions locally.
 *
 * <p>This transaction manager provides support for specifying the chain id for transactions as per
 * <a href="https://github.com/ethereum/EIPs/issues/155">EIP155</a>, as well as for locally signing
 * RawTransaction instances without broadcasting them.
 *
 * Inspired by https://github.com/web3j/web3j/blob/master/core/src/main/java/org/web3j/tx/RawTransactionManager.java
 * https://github.com/PegaSysEng/ethsigner/blob/master/ethsigner/signer/azure/src/main/java/tech/pegasys/ethsigner/signer/azure/AzureKeyVaultTransactionSigner.java
 */
public class KeyVaultTransactionManager extends TransactionManager {

    private final Web3j web3j;
    final KeyVaultClient client;

    private final long chainId;

    protected TxHashVerifier txHashVerifier = new TxHashVerifier();

    public static final String REVERT_ERR_STR =
            "Contract Call has been reverted by the EVM with the reason: '%s'.";

    public KeyVaultTransactionManager(Web3j web3j, KeyVaultClient client, long chainId) {
        super(web3j, client.getAddress());

        this.web3j = web3j;
        this.client = client;
        this.chainId = chainId;
    }

    public KeyVaultTransactionManager(
            Web3j web3j,
            KeyVaultClient client,
            long chainId,
            TransactionReceiptProcessor transactionReceiptProcessor) {
        super(transactionReceiptProcessor, client.getAddress());

        this.web3j = web3j;
        this.client = client;
        this.chainId = chainId;
    }

    public KeyVaultTransactionManager(
            Web3j web3j, KeyVaultClient client, long chainId, int attempts, long sleepDuration) {
        super(web3j, attempts, sleepDuration, client.getAddress());

        this.web3j = web3j;
        this.client = client;

        this.chainId = chainId;
    }

    public KeyVaultTransactionManager(Web3j web3j, KeyVaultClient client) {
        this(web3j, client, ChainIdLong.NONE);
    }

    public KeyVaultTransactionManager(
            Web3j web3j, KeyVaultClient client, int attempts, int sleepDuration) {
        this(web3j, client, ChainIdLong.NONE, attempts, sleepDuration);
    }

    protected BigInteger getNonce() throws IOException {
        EthGetTransactionCount ethGetTransactionCount =
                web3j.ethGetTransactionCount(getFromAddress(), DefaultBlockParameterName.PENDING)
                        .send();

        return ethGetTransactionCount.getTransactionCount();
    }

    public TxHashVerifier getTxHashVerifier() {
        return txHashVerifier;
    }

    public void setTxHashVerifier(TxHashVerifier txHashVerifier) {
        this.txHashVerifier = txHashVerifier;
    }

    @Override
    public EthSendTransaction sendTransaction(
            BigInteger gasPrice,
            BigInteger gasLimit,
            String to,
            String data,
            BigInteger value,
            boolean constructor)
            throws IOException {

        BigInteger nonce = getNonce();

        RawTransaction rawTransaction =
                RawTransaction.createTransaction(nonce, gasPrice, gasLimit, to, value, data);

        return signAndSend(rawTransaction);
    }

    @Override
    public String sendCall(String to, String data, DefaultBlockParameter defaultBlockParameter)
            throws IOException {
        EthCall ethCall =
                web3j.ethCall(
                                Transaction.createEthCallTransaction(getFromAddress(), to, data),
                                defaultBlockParameter)
                        .send();

        if (ethCall.isReverted()) {
            throw new ContractCallException(
                    String.format(REVERT_ERR_STR, ethCall.getRevertReason()));
        }
        return ethCall.getValue();
    }

    @Override
    public EthGetCode getCode(
            final String contractAddress, final DefaultBlockParameter defaultBlockParameter)
            throws IOException {
        return web3j.ethGetCode(contractAddress, defaultBlockParameter).send();
    }

    /*
     * @param rawTransaction a RawTransaction instance to be signed
     * @return The transaction signed and encoded without ever broadcasting it
     */
    public String sign(RawTransaction rawTransaction) {

        // Encode and hash the transaction
        byte[] bytesToSign;
        if (chainId == ChainIdLong.NONE) {
            bytesToSign = TransactionEncoder.encode(rawTransaction);
        } else {
            bytesToSign = TransactionEncoder.encode(rawTransaction, chainId);
        }
        byte[] hash = Hash.sha3(bytesToSign);

        // Sign using key Vault client
        ECDSASignature signature = client.sign(hash);

        // Work backwards to figure out the recovery id needed to recover the signature.
        // Used to derive msg.sender (address) in Ethereum clients
        final int recId = getRecoveryId(signature, hash);
        if (recId == -1) {
            throw new RuntimeException("Error generating recovery id from signature");
        }
        byte[] v = new byte[] {(byte) recId};
        byte[] r = Numeric.toBytesPadded(signature.r, 32);
        byte[] s = Numeric.toBytesPadded(signature.s, 32);

        Sign.SignatureData canonicalSig = new Sign.SignatureData(v, r, s);

        if (chainId != ChainIdLong.NONE) {
            // EIP-555 Prevent replay attacks
            canonicalSig = TransactionEncoder.createEip155SignatureData(canonicalSig, chainId);
        }

        // Finally RLP encode the signed transaction
        List<RlpType> values = TransactionEncoder.asRlpValues(rawTransaction, canonicalSig);
        RlpList rlpList = new RlpList(values);
        final byte[] serialisedBytes = RlpEncoder.encode(rlpList);

        return Numeric.toHexString(serialisedBytes);
    }

    public EthSendTransaction signAndSend(RawTransaction rawTransaction) throws IOException {
        String hexValue = sign(rawTransaction);
        EthSendTransaction ethSendTransaction = web3j.ethSendRawTransaction(hexValue).send();

        if (ethSendTransaction != null && !ethSendTransaction.hasError()) {
            String txHashLocal = Hash.sha3(hexValue);
            String txHashRemote = ethSendTransaction.getTransactionHash();
            if (!txHashVerifier.verify(txHashLocal, txHashRemote)) {
                throw new TxHashMismatchException(txHashLocal, txHashRemote);
            }
        }

        return ethSendTransaction;
    }

    private int getRecoveryId(ECDSASignature sig, byte[] hash) {
        BigInteger publicKey = client.getPublicKey();
        for (int i = 0; i < 2; i++) {
            final BigInteger k = Sign.recoverFromSignature(i, sig, hash);
            if (k != null && k.equals(publicKey)) {
                return i + 27;
            }
        }
        return -1;
    }
}
