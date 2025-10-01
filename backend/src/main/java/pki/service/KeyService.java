package pki.service;

import jakarta.xml.bind.DatatypeConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pki.util.AESUtil;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class KeyService {
    @Value("${app.master-key}")
    private String masterKey;
    private final static String ASYMMETRIC_KEY_ALGORITHM = "RSA";

    /**
     * Returns the master key as a byte array, converted from hex.
     */
    private byte[] getMasterKeyBytes() {
        return DatatypeConverter.parseHexBinary(masterKey);
    }

    public String generateWrappedKek() throws GeneralSecurityException {
        return generateKey(getMasterKeyBytes());
    }

    public String generateWrappedDek(String wrappedKek) throws GeneralSecurityException {
        byte[] kekBytes = unwrapKey(wrappedKek, getMasterKeyBytes());
        return generateKey(kekBytes);
    }

    public String wrapPrivateKey(PrivateKey privateKey, String wrappedDek, String wrappedKek) throws GeneralSecurityException {
        byte[] kekBytes = unwrapKey(wrappedKek, getMasterKeyBytes());
        byte[] dekBytes = unwrapKey(wrappedDek, kekBytes);
        return wrapKey(privateKey.getEncoded(), dekBytes);
    }

    public PrivateKey unwrapPrivateKey(String wrappedPrivateKey, String wrappedDek, String wrappedKek) throws GeneralSecurityException {
        byte[] kekBytes = unwrapKey(wrappedKek, getMasterKeyBytes());
        byte[] dekBytes = unwrapKey(wrappedDek, kekBytes);
        byte[] privateKeyBytes = unwrapKey(wrappedPrivateKey, dekBytes);
        return KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public String unwrapDek(String wrappedDek, String adminWrappedKek) throws GeneralSecurityException {
        byte[] kekBytes = unwrapKey(adminWrappedKek, getMasterKeyBytes());
        byte[] dekBytes = unwrapKey(wrappedDek, kekBytes);
        return Base64.getEncoder().encodeToString(dekBytes);
    }


    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ASYMMETRIC_KEY_ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(2048, random);
        return keyGen.generateKeyPair();
    }

    /**
     * Generates a new key and wraps it using the given wrapping key.
     */
    private String generateKey(byte[] wrappingKey) throws GeneralSecurityException {
        byte[] newKey = AESUtil.wrapNewKey(wrappingKey);
        return Base64.getEncoder().encodeToString(newKey);
    }

    /**
     * Unwraps the given key using the given wrapping key.
     */
    private byte[] unwrapKey(String wrapped, byte[] wrappingKey) throws GeneralSecurityException {
        byte[] wrappedKey = Base64.getDecoder().decode(wrapped);
        return AESUtil.unwrapKey(wrappedKey, wrappingKey);
    }

    /**
     * Wraps the given key using the given wrapping key.
     */
    private String wrapKey(byte[] toWrap, byte[] wrappingKey) throws GeneralSecurityException {
        byte[] wrappedKey = AESUtil.wrapKey(toWrap, wrappingKey);
        return Base64.getEncoder().encodeToString(wrappedKey);
    }
}
