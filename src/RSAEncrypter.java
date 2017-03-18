import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import com.sun.org.apache.xml.internal.security.utils.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.MGF1ParameterSpec;

public class RSAEncrypter {
    private final KeyReader keyReader;

    public RSAEncrypter(String privateKeyPath, String publicKeyPath) {
        keyReader = new KeyReader(privateKeyPath, publicKeyPath);
    }

    enum CipherMode {
        ENCRYPT(Cipher.ENCRYPT_MODE),
        DECRYPT(Cipher.DECRYPT_MODE);

        private int encryptMode;

        CipherMode(int encryptMode) {
            this.encryptMode = encryptMode;
        }

        public int get() {
            return encryptMode;
        }
    }

    public String decrypt(String ciphertext) throws Base64DecodingException, IOException, GeneralSecurityException{
        byte[] cipherbytes = Base64.decode(ciphertext);
        byte[] plainbytes = decryptBytes(cipherbytes);
        return new String(plainbytes, "UTF-8");
    }

    public String encrypt(String plaintext) throws IOException, GeneralSecurityException {
        byte[] plainbytes = plaintext.getBytes();
        byte[] cipherbytes = encryptBytes(plainbytes);
        return Base64.encode(cipherbytes);
    }

    private byte[] encryptBytes(byte[] plainbytes) throws IOException, GeneralSecurityException {
        Cipher cipher = createCipher(CipherMode.ENCRYPT, keyReader.getPublicKey());
        return cipher.doFinal(plainbytes);
    }

    private byte[] decryptBytes(byte[] cipherbytes) throws IOException, GeneralSecurityException {
        Cipher cipher = createCipher(CipherMode.DECRYPT, keyReader.getPrivateKey());
        return cipher.doFinal(cipherbytes);
    }

    private Cipher createCipher(CipherMode cipherMode, Key key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec algorithmConfigOptions = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        cipher.init(cipherMode.get(), key, algorithmConfigOptions);
        return cipher;
    }
}
