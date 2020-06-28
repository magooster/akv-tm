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

import org.junit.jupiter.api.Test;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthGetTransactionCount;

import net.iaminnovative.keyvault.AzureCryptoClient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class KeyVaultFastTransactionManagerTest {

    AzureCryptoClient azureCryptoClient = mock(AzureCryptoClient.class);
    Web3j web3j = mock(Web3j.class);

    private static final String FROM_ADDRESS = "3e55d41a06436461fc8ec5cda7ef088815660359";

    @Test
    void testGetNonce() throws IOException {
        when(azureCryptoClient.getAddress()).thenReturn(FROM_ADDRESS);
        EthGetTransactionCount ethGetTransactionCount = new EthGetTransactionCount();
        ethGetTransactionCount.setResult("0x1");

        Request<?, EthGetTransactionCount> transactionCountRequest = mock(Request.class);
        when(transactionCountRequest.send()).thenReturn(ethGetTransactionCount);
        when(web3j.ethGetTransactionCount(FROM_ADDRESS, DefaultBlockParameterName.PENDING))
                .thenReturn((Request) transactionCountRequest);

        KeyVaultFastTransactionManager transactionManager =
                new KeyVaultFastTransactionManager(web3j, azureCryptoClient);
        BigInteger firstNonce = transactionManager.getNonce();
        assertEquals(BigInteger.ONE, firstNonce);

        BigInteger secondNonce = transactionManager.getNonce();
        assertEquals(BigInteger.valueOf(2L), secondNonce);
    }
}
