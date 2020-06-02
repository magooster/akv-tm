package net.iaminnovative;

import org.web3j.crypto.ECDSASignature;

import java.math.BigInteger;
import java.util.Arrays;

public class Utils {

    public static final int PUBLIC_COORDINATE_SIZE = 32;
    public static final int PUBLIC_KEY_SIZE = 64;

    public static ECDSASignature toCanonicalSignature(byte[] signature) {

        // Grab the signature R and S values
        final BigInteger R = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
        final BigInteger S = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));

        // Canonicalise the signature - Ethereum constraint to ensure only one signature valid
        final ECDSASignature initialSignature = new ECDSASignature(R, S);
        return initialSignature.toCanonicalised();

    }

    public static BigInteger getPublicKey(byte[] affineX, byte[] affineY) {
        byte[] pubKey = new byte[PUBLIC_KEY_SIZE];

        System.arraycopy(affineX, 0, pubKey, 0, PUBLIC_COORDINATE_SIZE);
        System.arraycopy(affineY, 0, pubKey, PUBLIC_COORDINATE_SIZE, PUBLIC_COORDINATE_SIZE);

        return new BigInteger(1, pubKey);
    }



}
