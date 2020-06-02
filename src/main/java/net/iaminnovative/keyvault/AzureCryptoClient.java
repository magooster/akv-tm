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
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.google.common.primitives.Bytes;
import net.iaminnovative.Utils;
import org.web3j.crypto.ECDSASignature;
import org.web3j.crypto.Keys;

import net.iaminnovative.KeyVaultException;

/**
 * The AzureCryptoClient provides synchronous methods to perform cryptographic operations using EC
 * asymmetric keys. The identity used requires the get and sign permissions on the respective key
 * vault.
 */
public class AzureCryptoClient implements KeyVaultClient {

    public static final String UNAUTHORIZED_ERROR = "Key vault operation is forbidden by policy";

    public static final String BAD_PARAMETER_ERROR =
            "Key vault does not contain key with specified version";

    public static final String INVALID_KEY_ERROR = "Key vault does not contain specified key";

    public static final String INVALID_VAULT_ERROR_MSG = "Specified key vault (%s) does not exist.";

    public static final String INVALID_SIGNATURE_LENGTH = "";

    private final CryptographyClient cryptoClient;
    private final BigInteger publicKey;

    private static final String KEY_IDENTIFIER_PATTERN = "https://%s.vault.azure.net/keys/%s/%s";

    private static final int PUBLIC_COORDINATE_SIZE = 32;

    /**
     * Instantiates a new key vault using the Azure cryptography client
     *
     * @param keyId The key identifier within Azure Key Vault
     * @param credential The token credential to use when authorizing requests
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(String keyId, TokenCredential credential)
            throws KeyVaultException {

        try {
            this.cryptoClient =
                    new CryptographyClientBuilder()
                            .credential(credential)
                            .keyIdentifier(keyId)
                            .buildClient();

            /* Cache public key to avoid additional lookup */
            KeyVaultKey key = cryptoClient.getKey();
            publicKey = getPublicKey(key.getKey());
        } catch (final HttpResponseException ex) {
            if (ex.getResponse().getStatusCode() == 400) {
                throw new KeyVaultException(BAD_PARAMETER_ERROR, ex);
            }
            if (ex.getResponse().getStatusCode() == 404) {
                throw new KeyVaultException(INVALID_KEY_ERROR, ex);
            }
            if (ex.getResponse().getStatusCode() == 403) {
                throw new KeyVaultException(UNAUTHORIZED_ERROR, ex);
            }
            throw new KeyVaultException(ex);
        } catch (final RuntimeException ex) {
            final String exMessage;
            if (ex.getCause() instanceof UnknownHostException) {
                exMessage = String.format(INVALID_VAULT_ERROR_MSG, keyId);
            } else {
                exMessage = "Unknown";
            }
            throw new KeyVaultException(exMessage, ex);
        }
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client Uses the
     * DefaultAzureCredential
     *
     * @param keyId The key identifier
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(String keyId) throws KeyVaultException {
        this(keyId, new DefaultAzureCredentialBuilder().build());
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client Uses a
     * ManagedIdentityCredential
     *
     * @param keyId The key identifier
     * @param clientId The clientId of the managed identity
     * @throws KeyVaultException
     */
    public AzureCryptoClient(String keyId, String clientId) throws KeyVaultException {
        this(keyId, new ManagedIdentityCredentialBuilder().clientId(clientId).build());
    }

    /**
     * Instantiates a new key vault using the Azure cryptography client Uses the
     * DefaultAzureCredential
     *
     * @param keyVaultName - The key vault name
     * @param keyName - The key name
     * @param keyVersion - The key version
     * @throws KeyVaultException
     */
    public AzureCryptoClient(String keyVaultName, String keyName, String keyVersion)
            throws KeyVaultException {
        this(String.format(KEY_IDENTIFIER_PATTERN, keyVaultName, keyName, keyVersion));
    }

    public AzureCryptoClient(
            String keyVaultName, String keyName, String keyVersion, String clientId)
            throws KeyVaultException {
        this(
                String.format(KEY_IDENTIFIER_PATTERN, keyVaultName, keyName, keyVersion),
                new ManagedIdentityCredentialBuilder().clientId(clientId).build());
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
    public ECDSASignature sign(byte[] txDigest) throws KeyVaultException {
        try {
            System.out.println("sign with key");
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

    private static BigInteger getPublicKey(JsonWebKey key) {
        return Utils.getPublicKey(toBytesPadded(key.getX()), toBytesPadded(key.getY()));
    }

    public static byte[] toBytesPadded(byte[] value) {
        byte[] result = new byte[PUBLIC_COORDINATE_SIZE];

        int bytesLength;
        int srcOffset;
        if (value[0] == 0) {
            bytesLength = value.length - 1;
            srcOffset = 1;
        } else {
            bytesLength = value.length;
            srcOffset = 0;
        }

        if (bytesLength > PUBLIC_COORDINATE_SIZE) {
            throw new RuntimeException("Input is too large to put in byte array of size " + PUBLIC_COORDINATE_SIZE);
        }

        int destOffset = PUBLIC_COORDINATE_SIZE - bytesLength;
        System.arraycopy(value, srcOffset, result, destOffset, bytesLength);
        return result;
    }

}
