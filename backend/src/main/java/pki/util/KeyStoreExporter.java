package pki.util;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

@Component
public class KeyStoreExporter {
    public static byte[] createPkcs12Keystore(PrivateKey privateKey,
                                              Certificate[] chain,
                                              String alias,
                                              char[] password) throws KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, password);

        if (privateKey != null)
            ks.setKeyEntry(alias, privateKey, password, chain);
        else {
            if (chain != null && chain.length > 0) {
                ks.setCertificateEntry(alias, chain[0]);
            } else {
                throw new IllegalArgumentException("No certificate or chain provided");
            }
        }

        try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
            ks.store(os, password);
            return os.toByteArray();
        }
    }
}
