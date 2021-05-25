package edu.purdue.cuttlefish.crypto;

import java.math.BigInteger;

public abstract class AsymPHE<C> extends CryptoScheme {

    static final boolean ENABLE_RANDOM = false;

    // bitlength for modulo n
    static final int BITLENGTH = Integer.parseInt(System.getenv("CF_ASYM_KEYS_LEN"));
//    static final int BITLENGTH = 256;
//    static final int BITLENGTH = 512;
//    static final int BITLENGTH = 1024;

    // modulo
    public BigInteger n;

    // threshold that separates positive from negative numbers
    public BigInteger negThreshold;

    public AsymPHE(String publicKeyPath, String privateKeyPath) {
        super(publicKeyPath, privateKeyPath);
    }

    /**
     * Generate a key for the cipher.
     */
    public abstract void keyGen();

    /**
     * Encrypt the given message
     */
    public abstract C encrypt(long message);

    /**
     * Decrypt the given ciphertext.
     */
    public abstract long decrypt(C ciphertext);

    /**
     * Setup the threshold between positive and negative numbers.
     */
    public void setupNegative(int negDivisor) {
        negThreshold = null;
        if (negDivisor != 1)
            negThreshold = n.divide(BigInteger.valueOf(negDivisor));
    }

    /**
     * Shift the given message to allow representing negative numbers.
     */
    public BigInteger handleNegative(BigInteger m) {
        if (negThreshold != null && m.compareTo(negThreshold) >= 0)
            m = m.subtract(n);
        return m;
    }

}
