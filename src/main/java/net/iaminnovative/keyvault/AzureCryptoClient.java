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
package net.iaminnovative.keyvault;

import java.math.BigInteger;
import java.net.UnknownHostException;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpClient;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Keys;

import net.iaminnovative.KeyVaultException;
import net.iaminnovative.Utils;

/**
 * The AzureCryptoClient provides synchronous methods to perform cryptographic operations using EC
 * asymmetric keys. The identity used requires the get and sign permissions on the respective key
 * vault.
 */
public class AzureCryptoClient implements KeyVaultClient {

    public static final String UNAUTHORIZED_ERROR = "Key vault operation is forbidden by policy.";

    public static final String INVALID_KEY_ERROR = "Key vault does not contain specified key";

    public static final String INVALID_VAULT_ERROR_MSG = "Specified key vault does not exist.";

    public static final String INVALID_SIGNATURE_LENGTH = "Invalid signature";

    private final CryptographyClient cryptoClient;
    private final BigInteger publicKey;

    /**
     * Instantiates a new key vault using the Azure cryptography client
     *
     * @param cryptoClient An
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(final CryptographyClient cryptoClient)  throws KeyVaultException {

        try {
            this.cryptoClient = cryptoClient;
            /* Cache public key to avoid additional lookup */
            KeyVaultKey key = cryptoClient.getKey();
            publicKey = getPublicKey(key.getKey());
        } catch (final HttpResponseException ex) {
            final int statusCode = ex.getResponse().getStatusCode();
            if (statusCode == 400 || statusCode == 404) {
                throw new KeyVaultException(INVALID_KEY_ERROR, ex);
            }
            if (statusCode == 403) {
                throw new KeyVaultException(UNAUTHORIZED_ERROR, ex);
            }
            throw new KeyVaultException(ex);
        } catch (final RuntimeException ex) {
            final String exMessage;
            if (ex.getCause() instanceof UnknownHostException) {
                exMessage = INVALID_VAULT_ERROR_MSG;
            } else {
                exMessage = "Unknown";
            }
            throw new KeyVaultException(exMessage, ex);
        }
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client
     *
     * @param keyId The key identifier
     * @param credential Azure token credential
     * @param httpClient HttpClient to use for requests
     * @throws KeyVaultException
     */
    public AzureCryptoClient(String keyId, TokenCredential credential, HttpClient httpClient)
            throws KeyVaultException {
        this(
                new CryptographyClientBuilder()
                        .credential(credential)
                        .httpClient(httpClient)
                        .keyIdentifier(keyId)
                        .buildClient());
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client
     *
     * @param keyId The key identifier
     * @param credential Azure token credential
     * @throws KeyVaultException
     */
    public AzureCryptoClient(final String keyId, final TokenCredential credential) throws KeyVaultException {
        this(
                new CryptographyClientBuilder()
                        .credential(credential)
                        .keyIdentifier(keyId)
                        .buildClient());
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client Uses the
     * DefaultAzureCredential
     *
     * @param keyId The key identifier
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(final String keyId) throws KeyVaultException {
        this(keyId, new DefaultAzureCredentialBuilder().build());
    }

    /**
     * Gets the public part of the configured key.
     *
     * @return The public key.
     */
    public BigInteger getPublicKey() {
        return publicKey;
    }

    /**
     * Gets tha Ethereum address of the configured key.
     *
     * @return The Ethereum address as a HEX encoded string.
     */
    public String getAddress() {
        return "0x" + Keys.getAddress(getPublicKey());
    }

    /**
     * Creates a signature from a digest using the configured key.
     *
     * @param txDigest The transaction digest (RLP encoded transaction) to be signed.
     * @return The signature.
     * @throws KeyVaultException - when a key vault error occurs.
     */
    public ECDSASignature sign(final byte[] txDigest) throws KeyVaultException {
        try {
            SignResult result = cryptoClient.sign(SignatureAlgorithm.ES256K, txDigest);
            if (result.getSignature().length > 64) {
                throw new KeyVaultException(INVALID_SIGNATURE_LENGTH);
            }
            return Utils.toCanonicalSignature(result.getSignature());
        } catch (HttpResponseException ex) {
            if (ex.getResponse().getStatusCode() == 404) {
                throw new KeyVaultException(INVALID_KEY_ERROR, ex);
            }
            if (ex.getResponse().getStatusCode() == 403) {
                throw new KeyVaultException(UNAUTHORIZED_ERROR, ex);
            }
            throw new KeyVaultException(ex);
        }
    }

    private static BigInteger getPublicKey(final JsonWebKey key) {
        return Utils.getPublicKey(key.getX(), key.getY());
    }
}
