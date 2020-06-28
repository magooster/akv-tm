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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.azure.core.credential.TokenCredential;
import com.azure.core.util.polling.SyncPoller;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.models.DeletedKey;
import com.azure.security.keyvault.keys.models.JsonWebKey;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import net.iaminnovative.KeyVaultException;

import static net.iaminnovative.keyvault.AzureCryptoClient.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

@ExtendWith(KeyVaultConfigured.class)
public class AzureCryptoClientTest {

    CryptographyClient cryptoClient = mock(CryptographyClient.class);
    private static final String FROM_ADDRESS = "3e55d41a06436461fc8ec5cda7ef088815660359";

    private static final Map<String, String> keys;

    static {
        keys = new HashMap<>();
        keys.put(
                "fcc168dba3e7f15a1f8cceb927854567e05357a9",
                "48bc3d6cb72cd71bc5bd9193cbee79cd784be0e928c473e6394fe8c71a287783");
        keys.put(
                "15d7a3397d86e7cecb8cd08d4ae07543617ecd20",
                "860d857178c57044f1f8cd23e6bd2b5ca192f2bb0e27562565d34d33563115e7");
    }

    private static final Map<String, String> keyVaultKeys = new HashMap<>();
    private static final Map<String, BigInteger> publicKeys = new HashMap<>();

    private static final String KEY_VAULT_URI =
            "https://" + System.getenv("AZURE_KEY_VAULT_NAME") + ".vault.azure.net/";

    @BeforeAll
    static void setupVault() throws NoSuchProviderException, NoSuchAlgorithmException {

        Security.addProvider(new BouncyCastleProvider());

        KeyClient keyClient =
                new KeyClientBuilder()
                        .vaultUrl(KEY_VAULT_URI)
                        .credential(new DefaultAzureCredentialBuilder().build())
                        .buildClient();

        keys.forEach(
                (address, privateKeyHex) -> {
                    Bytes32 privateKeyBytes = Bytes32.fromHexString(privateKeyHex);

                    BigInteger s = privateKeyBytes.toUnsignedBigInteger();

                    KeyFactory keyFactory = null;
                    try {
                        keyFactory = KeyFactory.getInstance("ECDSA", "BC");
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    } catch (NoSuchProviderException e) {
                        e.printStackTrace();
                    }

                    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
                    ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(s, ecSpec);

                    BCECPrivateKey privateKey = null;
                    try {
                        privateKey = (BCECPrivateKey) keyFactory.generatePrivate(privateKeySpec);
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }

                    ECPoint Q = ecSpec.getG().multiply((privateKey).getD());

                    ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);

                    BCECPublicKey publicKey = null;
                    try {
                        publicKey = (BCECPublicKey) keyFactory.generatePublic(pubSpec);
                    } catch (InvalidKeySpecException e) {
                        e.printStackTrace();
                    }

                    final byte[] publicKeyBytes = publicKey.getQ().getEncoded(false);

                    KeyPair keyPair = new KeyPair(publicKey, privateKey);

                    final JsonWebKey jsonWebKey =
                            JsonWebKey.fromEc(keyPair, Security.getProvider("BC"));
                    final KeyVaultKey importedKey = keyClient.importKey(address, jsonWebKey);

                    keyVaultKeys.put(importedKey.getId(), address);

                    publicKeys.put(
                            importedKey.getId(),
                            new BigInteger(
                                    1,
                                    Arrays.copyOfRange(publicKeyBytes, 1, publicKeyBytes.length)));
                });
    }

    @AfterAll
    static void cleanupVault() {

        KeyClient client =
                new KeyClientBuilder()
                        .vaultUrl(KEY_VAULT_URI)
                        .credential(new DefaultAzureCredentialBuilder().build())
                        .buildClient();

        keys.forEach(
                (address, privateKeyHex) -> {
                    SyncPoller<DeletedKey, Void> deletedKeyPoller = client.beginDeleteKey(address);
                    deletedKeyPoller.waitForCompletion();
                });

        for (DeletedKey deletedKey : client.listDeletedKeys()) {
            client.purgeDeletedKey(deletedKey.getName());
        }
    }

    @Test
    public void testGetFromAddress() {
        keyVaultKeys.forEach(
                (id, address) -> {
                    AzureCryptoClient client = new AzureCryptoClient(id);
                    assertEquals("0x" + address, client.getAddress());
                });
    }

    @Test
    public void testGetPublicKey() {
        publicKeys.forEach(
                (id, publicKey) -> {
                    AzureCryptoClient client = new AzureCryptoClient(id);
                    assertEquals(publicKey, client.getPublicKey());
                });
    }

    @Test
    public void testInvalidKeyException() {
        String invalidKeyId = KEY_VAULT_URI + "/keys/invalid/224120347bc041d682d0bf0e7f8f9ec6";
        Exception exception =
                assertThrows(
                        KeyVaultException.class,
                        () -> {
                            new AzureCryptoClient(invalidKeyId);
                        });
        assertEquals(INVALID_KEY_ERROR, exception.getMessage());
    }

    @Test
    public void testBadParameterException() {
        String keyId = keyVaultKeys.keySet().toArray()[0].toString();
        String invalidKeyId = keyId.substring(0, keyId.length() - 4);
        Exception exception =
                assertThrows(
                        KeyVaultException.class,
                        () -> {
                            new AzureCryptoClient(invalidKeyId);
                        });
        assertEquals(INVALID_KEY_ERROR, exception.getMessage());
    }

    @Test
    public void testInvalidHostException() {
        String invalidKeyId =
                "https://unlikelytoexist.vault.azure.net/keys/invalid/224120347bc041d682d0bf0e7f8f9ec6";
        Exception exception =
                assertThrows(
                        KeyVaultException.class,
                        () -> {
                            new AzureCryptoClient(invalidKeyId);
                        });
        assertEquals(INVALID_VAULT_ERROR_MSG, exception.getMessage());
    }

    @Test
    public void testValidCustomCredentials() {
        TokenCredential credential =
                new ClientSecretCredentialBuilder()
                        .tenantId(System.getenv("AZURE_TENANT_ID"))
                        .clientId(System.getenv("AZURE_CLIENT_ID"))
                        .clientSecret(System.getenv("AZURE_CLIENT_SECRET"))
                        .build();

        keyVaultKeys.forEach(
                (id, address) -> {
                    AzureCryptoClient client = new AzureCryptoClient(id, credential);
                    assertEquals("0x" + address, client.getAddress());
                });
    }

    @Test
    public void testInvalidCredentialsException() {
        TokenCredential credential =
                new ClientSecretCredentialBuilder()
                        .tenantId(System.getenv("AZURE_TENANT_ID"))
                        .clientId(System.getenv("AZURE_CLIENT_ID"))
                        .clientSecret("1234")
                        .build();
        Exception exception =
                assertThrows(
                        KeyVaultException.class,
                        () -> {
                            new AzureCryptoClient(
                                    keyVaultKeys.keySet().toArray()[0].toString(), credential);
                        });
        assertEquals("Unknown", exception.getMessage());
    }
}
