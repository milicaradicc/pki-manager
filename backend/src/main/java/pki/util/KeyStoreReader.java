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
            System.err.println("Error loading JKS: " + e.getMessage());
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    public Certificate readCertificate(String keyStoreFile, String keyStorePass, String alias) throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
        keyStore.load(in, keyStorePass.toCharArray());

        if(keyStore.isKeyEntry(alias) || keyStore.isCertificateEntry(alias)) {
            Certificate cert = keyStore.getCertificate(alias);
            return cert;
        }
        return null;
    }

    public Certificate[] readCertificateChain(String keyStoreFile, String keyStorePass, String alias) throws KeyStoreException, NoSuchProviderException, IOException, CertificateException, NoSuchAlgorithmException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
        keyStore.load(in, keyStorePass.toCharArray());
        if (keyStore.isKeyEntry(alias)) {
            return keyStore.getCertificateChain(alias);
        } else if (keyStore.isCertificateEntry(alias)) {
            return new Certificate[] { keyStore.getCertificate(alias) };
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

