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

/** The interface for the KeyVaultClient class */
public interface KeyVaultClient {

    /**
     * Get the public key for the private key managed by the key client
     *
     * @return The public key.
     */
    byte[] getPublicKey();

    /**
     * Get the Ethereum address for the private key managed by the key client
     *
     * @return The Ethereum address.
     */
    String getAddress();

    /**
     * Signs the message digest (keccak256 hash) using the private key managed by the key client
     *
     * @param msgHash - The content from which signature is to be created.
     * @return The signature.
     */
    byte[] sign(byte[] msgHash);
}
