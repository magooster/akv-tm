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
import org.web3j.crypto.Keys;

import net.iaminnovative.KeyVaultException;

/**
 * The AzureCryptoClient provides synchronous methods to perform cryptographic operations using EC asymmetric keys.
 * The identity used requires the get and sign permissions on the respective key vault.
 */
public class AzureCryptoClient implements KeyVaultClient {

    public static final String UNAUTHORIZED_ERROR =
            "Key vault operation is forbidden by policy";

    public static final String BAD_PARAMETER_ERROR =
            "Key vault does not contain key with specified version";

    public static final String INVALID_KEY_ERROR = "Key vault does not contain specified key";

    public static final String INVALID_VAULT_ERROR_MSG = "Specified key vault (%s) does not exist.";

    private final CryptographyClient cryptoClient;
    private byte[] publicKey = null;

    private static final String KEY_IDENTIFIER_PATTERN = "https://%s.vault.azure.net/keys/%s/%s";

    /**
     * Instantiates a new key vault using the Azure cryptography client
     * @param keyId The key identifier within Azure Key Vault
     * @param credential The token credential to use when authorizing requests
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(String keyId, TokenCredential credential) throws KeyVaultException {

        try {
            this.cryptoClient =
                    new CryptographyClientBuilder()
                            .credential(credential)
                            .keyIdentifier(keyId)
                            .buildClient();

            /* Cache public key to avoid additional lookup */
            KeyVaultKey key = cryptoClient.getKey();
            JsonWebKey jwk = key.getKey();
            publicKey = Bytes.concat(jwk.getX(), jwk.getY());
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
     *
     * @param keyId The key identifier within Azure Key Vault
     * @throws KeyVaultException When the key vault operation throws an error
     */
    public AzureCryptoClient(String keyId) throws KeyVaultException {
        this(keyId, new DefaultAzureCredentialBuilder().build());
    }

    public AzureCryptoClient(String keyId, String clientId) throws KeyVaultException {
        this(keyId, new ManagedIdentityCredentialBuilder().clientId(clientId).build());
    }

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
     * @return The public key.
     */
    public byte[] getPublicKey() {
        return publicKey;
    }

    /**
     * Gets tha Ethereum address of the configured key.
     * @return The Ethereum address as a HEX encoded string.
     */
    public String getAddress() {
        BigInteger publicKey = new BigInteger(1, this.publicKey);
        return "0x" + Keys.getAddress(publicKey);
    }

    /**
     * Creates a signature from a digest using the configured key.
     * @param msgHash The transaction digest (RLP encoded transaction) to be signed.
     * @return The signature.
     * @throws KeyVaultException - when a key vault error occurs.
     */
    public byte[] sign(byte[] msgHash) throws KeyVaultException {
        try {
            SignResult result = cryptoClient.sign(SignatureAlgorithm.ES256K, msgHash);
            return result.getSignature();
        }
        catch(HttpResponseException ex) {
            if (ex.getResponse().getStatusCode() == 404) {
                throw new KeyVaultException(INVALID_KEY_ERROR, ex);
            }
            if (ex.getResponse().getStatusCode() == 403) {
                throw new KeyVaultException(UNAUTHORIZED_ERROR, ex);
            }
            throw new KeyVaultException(ex);
        }
    }
}
