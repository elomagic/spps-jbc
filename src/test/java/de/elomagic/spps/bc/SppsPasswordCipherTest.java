package de.elomagic.spps.bc;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class SppsPasswordCipherTest {

    @Test
    void testEncrypt() {

        SppsPasswordCipher cipher = new SppsPasswordCipher();

        String secret = "MyTestSecret";

        char[] encryptedSecret = cipher.encrypt("MyTestSecret");

        Assertions.assertEquals(secret, SimpleCrypt.decryptToString(String.valueOf(encryptedSecret)));
        Assertions.assertNull(cipher.encrypt(null));

    }

    @Test
    void testDecrypt() {

        SppsPasswordCipher cipher = new SppsPasswordCipher();

        String secret = "MyTestSecret";

        char[] encryptedSecret = SimpleCrypt.encrypt(secret).toCharArray();

        Assertions.assertEquals(secret, cipher.decrypt(encryptedSecret));
        Assertions.assertEquals(secret, cipher.decrypt(Arrays.copyOfRange(encryptedSecret, 1, encryptedSecret.length-1)));
        Assertions.assertNull(cipher.decrypt(null));

    }


}
