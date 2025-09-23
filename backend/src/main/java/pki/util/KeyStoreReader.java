package pki.util;

import org.springframework.stereotype.Component;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

@Component
public class KeyStoreReader {
    private KeyStore keyStore;

    public KeyStoreReader() {
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore ks = KeyStore.getInstance("JKS", "SUN");
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
        ks.load(in, keyStorePass.toCharArray());

        if(ks.isKeyEntry(alias)) {
            Certificate cert = ks.getCertificate(alias);
            return cert;
        }
        return null;
    }

    public void downloadCertificate(Certificate certificate) {
        try (FileOutputStream fos = new FileOutputStream("example_certificate.cer")) {
            fos.write(certificate.getEncoded());
        } catch (FileNotFoundException | CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}

