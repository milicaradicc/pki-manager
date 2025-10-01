package pki.util;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class AESUtil {
    private static final int AES_KEY_SIZE = 256; // bits
    private static final int GCM_IV_LENGTH = 12; // bytes
    private static final int GCM_TAG_LENGTH = 128; // bits

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    /**
     * Generates a new key and wraps it using the given wrapping key.
     */
    public static byte[] wrapNewKey(byte[] wrappingKey) throws GeneralSecurityException {
        return wrapKey(generateAESKey().getEncoded(), wrappingKey);
    }

    /**
     * Wraps the given key using the given wrapping key. Functionally equivalent to {@link #encrypt(byte[], byte[])}.
     */
    public static byte[] wrapKey(byte[] toWrap, byte[] wrappingKey) throws GeneralSecurityException {
        return encrypt(toWrap, wrappingKey);
    }

    /**
     * Unwraps the given key using the given wrapping key. Functionally equivalent to {@link #decrypt(byte[], byte[])}.
     */
    public static byte[] unwrapKey(byte[] wrapped, byte[] wrappingKey) throws GeneralSecurityException {
        return decrypt(wrapped, wrappingKey);
    }

    public static byte[] encrypt(byte[] value, byte[] encryptionKey) throws GeneralSecurityException {
        SecretKey key = new SecretKeySpec(encryptionKey, "AES");

        // Random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Encrypt with AES-GCM
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] ciphertext = cipher.doFinal(value);

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);

        return result;
    }

    public static byte[] decrypt(byte[] ciphertextWithIv, byte[] encryptionKey) throws GeneralSecurityException {
        SecretKey key = new SecretKeySpec(encryptionKey, "AES");

        // Extract IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(ciphertextWithIv, 0, iv, 0, iv.length);

        // Extract ciphertext
        byte[] ciphertext = new byte[ciphertextWithIv.length - iv.length];
        System.arraycopy(ciphertextWithIv, iv.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        return cipher.doFinal(ciphertext);
    }

    public static SecretKey toSecretKey(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }
}

