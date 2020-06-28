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
package net.iaminnovative;

import java.math.BigInteger;
import java.util.Arrays;

import org.web3j.crypto.ECDSASignature;

public class Utils {

    public static final int PUBLIC_COORDINATE_SIZE = 32;
    public static final int PUBLIC_KEY_SIZE = 64;

    /**
     * Convert a byte array containing a 64 byte signature to a valid Ethereum signature
     *
     * @param signature byte array containing a signature
     * @return A valid Ethereum protocol signature
     */
    public static ECDSASignature toCanonicalSignature(byte[] signature) {

        // Grab the signature R and S values
        final BigInteger R = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
        final BigInteger S = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

        // Canonicalise the signature - Ethereum constraint to ensure only one signature valid
        final ECDSASignature initialSignature = new ECDSASignature(R, S);
        return initialSignature.toCanonicalised();
    }

    /**
     * Convert public key coordinates for a public key to a BigInteger representation
     *
     * @param affineX byte array containing the X point
     * @param affineY byte array containing the Y point
     * @return BigInteger representing the 64 byte public key
     */
    public static BigInteger getPublicKey(byte[] affineX, byte[] affineY) {
        byte[] pubKey = new byte[PUBLIC_KEY_SIZE];

        System.arraycopy(toBytesPadded(affineX), 0, pubKey, 0, PUBLIC_COORDINATE_SIZE);
        System.arraycopy(
                toBytesPadded(affineY), 0, pubKey, PUBLIC_COORDINATE_SIZE, PUBLIC_COORDINATE_SIZE);

        return new BigInteger(1, pubKey);
    }

    /**
     * Pad a byte array to 32 bytes
     *
     * @param value the byte array containing a public key point
     * @return A 32 byte array
     */
    private static byte[] toBytesPadded(byte[] value) {
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
            throw new RuntimeException(
                    "Input is too large to put in byte array of size " + PUBLIC_COORDINATE_SIZE);
        }

        int destOffset = PUBLIC_COORDINATE_SIZE - bytesLength;
        System.arraycopy(value, srcOffset, result, destOffset, bytesLength);
        return result;
    }
}
