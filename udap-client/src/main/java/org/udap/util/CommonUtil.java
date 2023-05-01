package org.udap.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.X509CertUtils;

/**
 *
 * Common Utility helper methods. Some methods maybe pruned / refined further
 * depending on their usefulness
 *
 * @author Brett P Stringham
 *
 */
public class CommonUtil {

    CommonUtil() {

    }

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static String getObjectAsJson(Object obj) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(obj);
    }

    public static X509Certificate readX509File(URI certificateUri) throws IOException {
        byte[] x509Bytes = Files.readAllBytes(Paths.get(certificateUri));

        return X509CertUtils.parse(x509Bytes);
    }

    public static RSAKey getPublicKey(final X509Certificate x509Cert) throws JOSEException {
        // Retrieve public key as RSA JWK
        return RSAKey.parse(x509Cert);
    }
    
    /**
     * For now -- assumes a single private key at the location provided by the URI
     * @param privateKeyUri
     * @param privateKeySecret
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws FileNotFoundException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static PrivateKey getPrivateKey(URI privateKeyUri, char[] privateKeySecret) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        final KeyStore keystore = KeyStore.getInstance("PKCS12");

        final Path keyPath = Paths.get(privateKeyUri);

        try (FileInputStream ks = new FileInputStream(keyPath.toFile())) {
            keystore.load(ks, privateKeySecret);

            final Enumeration<String> e = keystore.aliases();
            if (e.hasMoreElements()) {
                String keyAlias = e.nextElement();
                return (PrivateKey) keystore.getKey(keyAlias, privateKeySecret);
            }
        }

        return null;
    }

    /**
     * Get JwkSet from PKCS12 file
     * @param privateKeyUri
     * @param privateKeySecret
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException
     */
    public static JWKSet getJwkSetFromPkcs12(URI privateKeyUri, char[] privateKeySecret) throws KeyStoreException,
            IOException, NoSuchAlgorithmException, CertificateException {
        final KeyStore keystore = KeyStore.getInstance("PKCS12");

        final Path keyPath = Paths.get(privateKeyUri);

        try (FileInputStream ks = new FileInputStream(keyPath.toFile())) {
            keystore.load(ks, privateKeySecret);

            return JWKSet.load(keystore, (final String name) -> privateKeySecret);
        }
    }

}
