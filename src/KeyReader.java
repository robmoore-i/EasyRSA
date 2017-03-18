import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyReader {
    private final String privateKeyPath;
    private final String publicKeyPath;

    public KeyReader(String privateKeyPath, String publicKeyPath) {
        this.privateKeyPath = privateKeyPath;
        this.publicKeyPath = publicKeyPath;
    }

    public Key getPrivateKey() throws IOException, GeneralSecurityException {
        byte[] keyBytes = getKeyBytes(privateKeyPath);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public Key getPublicKey() throws IOException, GeneralSecurityException {
        byte[] keyBytes = getKeyBytes(publicKeyPath);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private byte[] getKeyBytes(String keyFilePath) throws IOException {
        Path keyPath = new File(keyFilePath).toPath();
        return Files.readAllBytes(keyPath);
    }

    public String publicKeyToPEMString() throws IOException, GeneralSecurityException {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(getPublicKey().getEncoded());
        return "-----BEGIN PUBLIC KEY-----" + Base64.encode(spec.getEncoded()) + "-----END PUBLIC KEY-----";
    }
}
