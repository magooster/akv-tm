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

import net.iaminnovative.Utils;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Hash;
import org.web3j.crypto.RawTransaction;
import org.web3j.crypto.TransactionEncoder;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.*;
import org.web3j.tx.gas.DefaultGasProvider;
import org.web3j.utils.Numeric;

import net.iaminnovative.keyvault.AzureCryptoClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class KeyVaultTransactionManagerTest {

    AzureCryptoClient azureCryptoClient = mock(AzureCryptoClient.class);
    Web3j web3j = mock(Web3j.class);

    private static final String PUBLIC_KEY =
            "0xb0cbafae9af1fcddd9476768dc1ae5f7ee56b515602afde47a7cdd4870a92475d48674de0a55fee9113360ff8ffab5f7eab7ea388c622e83e0aaaaa1459ff1e2";
    private static final String SIGNATURE =
            "0xd2276a047828f5d3272f73b78003de19a8d075faa4b1daecfbeb795d0a23390f97a9dede4aa3d5a02938febc3f59d40b67b15bde69f32724740c6068526c26c2";
    private static final String TX_DATA =
            "0x6057361d0000000000000000000000000000000000000000000000000000000000000064";
    private static final String FROM_ADDRESS = "3e55d41a06436461fc8ec5cda7ef088815660359";
    private static final String SIGNED_TX =
            "0xf8880184f46109008389544094f0116acf925a7439efe80b3341aa0b2b1806dafd80a46057361d00000000000000000000000000000000000000000000000000000000000000641ca0d2276a047828f5d3272f73b78003de19a8d075faa4b1daecfbeb795d0a23390fa068562121b55c2a5fd6c70143c0a62bf352fd8108455579174bc5fe247dca1a7f";

    RawTransaction rawTransaction =
            RawTransaction.createTransaction(
                    BigInteger.ONE,
                    DefaultGasProvider.GAS_PRICE,
                    DefaultGasProvider.GAS_LIMIT,
                    "0xf0116acf925a7439efe80b3341aa0b2b1806dafd",
                    BigInteger.ZERO,
                    TX_DATA);

    ECDSASignature signature = Utils.toCanonicalSignature(Numeric.hexStringToByteArray(SIGNATURE));
    BigInteger publicKey = Numeric.toBigInt(PUBLIC_KEY);

    @Test
    public void testGetFromAddress() {
        when(azureCryptoClient.getAddress()).thenReturn(FROM_ADDRESS);
        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);

        String fromAddress = keyVaultTransactionManager.getFromAddress();
        assertEquals(FROM_ADDRESS, fromAddress);
    }

    @Test
    public void testSendCall() throws IOException {
        when(azureCryptoClient.getAddress()).thenReturn(FROM_ADDRESS);

        EthCall ethCall = new EthCall();
        ethCall.setResult("test");

        Request<?, EthCall> ethCallRequest = mock(Request.class);
        when(ethCallRequest.send()).thenReturn(ethCall);
        when(web3j.ethCall(any(), any())).thenReturn((Request) ethCallRequest);

        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);
        String value =
                keyVaultTransactionManager.sendCall("", "", DefaultBlockParameterName.PENDING);
        assertEquals("test", value);
    }

    @Test
    void testGetNonce() throws IOException {
        when(azureCryptoClient.getAddress()).thenReturn(FROM_ADDRESS);
        EthGetTransactionCount ethGetTransactionCount = new EthGetTransactionCount();
        ethGetTransactionCount.setResult("0x1");

        Request<?, EthGetTransactionCount> transactionCountRequest = mock(Request.class);
        when(transactionCountRequest.send()).thenReturn(ethGetTransactionCount);
        when(web3j.ethGetTransactionCount(FROM_ADDRESS, DefaultBlockParameterName.PENDING))
                .thenReturn((Request) transactionCountRequest);

        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);
        BigInteger nonce = keyVaultTransactionManager.getNonce();
        assertEquals(BigInteger.ONE, nonce);
    }

    @Test
    void testSign() {

        when(azureCryptoClient.getPublicKey()).thenReturn(publicKey);

        byte[] bytesToSign = TransactionEncoder.encode(rawTransaction);
        byte[] hash = Hash.sha3(bytesToSign);

        when(azureCryptoClient.sign(hash)).thenReturn(signature);

        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);
        String signedTx = keyVaultTransactionManager.sign(rawTransaction);
        assertEquals(SIGNED_TX, signedTx);
    }

    @Test
    void testSignAndSend() throws IOException {

        EthSendTransaction ethSendTransaction = new EthSendTransaction();
        ethSendTransaction.setResult(Hash.sha3(SIGNED_TX));

        Request<?, EthSendTransaction> sendRawTransactionRequest = mock(Request.class);
        when(sendRawTransactionRequest.send()).thenReturn(ethSendTransaction);
        when(web3j.ethSendRawTransaction(SIGNED_TX))
                .thenReturn((Request) sendRawTransactionRequest);

        when(azureCryptoClient.getPublicKey()).thenReturn(publicKey);
        byte[] bytesToSign = TransactionEncoder.encode(rawTransaction);
        byte[] hash = Hash.sha3(bytesToSign);

        when(azureCryptoClient.sign(hash)).thenReturn(signature);

        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);
        EthSendTransaction result = keyVaultTransactionManager.signAndSend(rawTransaction);

        assertEquals(Hash.sha3(SIGNED_TX), result.getResult());
    }

    @Test
    public void testSendTransaction() throws IOException {

        when(azureCryptoClient.getAddress()).thenReturn(FROM_ADDRESS);
        EthGetTransactionCount ethGetTransactionCount = new EthGetTransactionCount();
        ethGetTransactionCount.setResult("0x1");

        Request<?, EthGetTransactionCount> transactionCountRequest = mock(Request.class);
        when(transactionCountRequest.send()).thenReturn(ethGetTransactionCount);
        when(web3j.ethGetTransactionCount(FROM_ADDRESS, DefaultBlockParameterName.PENDING))
                .thenReturn((Request) transactionCountRequest);

        EthSendTransaction ethSendTransaction = new EthSendTransaction();
        ethSendTransaction.setResult(Hash.sha3(SIGNED_TX));

        Request<?, EthSendTransaction> sendRawTransactionRequest = mock(Request.class);
        when(sendRawTransactionRequest.send()).thenReturn(ethSendTransaction);
        when(web3j.ethSendRawTransaction(SIGNED_TX))
                .thenReturn((Request) sendRawTransactionRequest);

        when(azureCryptoClient.getPublicKey()).thenReturn(publicKey);
        byte[] bytesToSign = TransactionEncoder.encode(rawTransaction);
        byte[] hash = Hash.sha3(bytesToSign);

        when(azureCryptoClient.sign(hash)).thenReturn(signature);

        KeyVaultTransactionManager keyVaultTransactionManager =
                new KeyVaultTransactionManager(web3j, azureCryptoClient);

        EthSendTransaction result =
                keyVaultTransactionManager.sendTransaction(
                        DefaultGasProvider.GAS_PRICE,
                        DefaultGasProvider.GAS_LIMIT,
                        "0xf0116acf925a7439efe80b3341aa0b2b1806dafd",
                        TX_DATA,
                        BigInteger.ZERO,
                        false);

        assertEquals(Hash.sha3(SIGNED_TX), result.getResult());
    }
}
