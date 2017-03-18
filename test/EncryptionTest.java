import com.sun.org.apache.xml.internal.security.exceptions.Base64DecodingException;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class EncryptionTest {
    private void runKeysScript(String scriptName) throws InterruptedException {
        ExecutorService executorService = Executors.newSingleThreadExecutor();
        executorService.execute(() -> {
            try {
                Runtime.getRuntime().exec("keys/" + scriptName);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });

        executorService.awaitTermination(3, TimeUnit.SECONDS);
        executorService.shutdown();
    }

    private void generateKeys() throws IOException, InterruptedException {
        runKeysScript("genkeys.sh");
    }

    private void deleteKeys() throws InterruptedException {
        runKeysScript("deletekeys.sh");
    }

    @Test
    public void canEncryptAndDecrypt() throws IOException, GeneralSecurityException, Base64DecodingException, InterruptedException {
        generateKeys();
        RSAEncrypter rsaEncrypter = new RSAEncrypter("keys/private.der", "keys/public.der");
        String plaintext = "Hello world!";

        String encrypted = rsaEncrypter.encrypt(plaintext);
        String decrypted = rsaEncrypter.decrypt(encrypted);

        assertNotNull(encrypted);
        assertNotNull(decrypted);
        assertTrue(encrypted.length() > 20); // todo: implement function "isGibberish(String s)"
        assertEquals(plaintext, decrypted);
        deleteKeys();
    }
}
