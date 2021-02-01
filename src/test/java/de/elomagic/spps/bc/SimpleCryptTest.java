package de.elomagic.spps.bc;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

class SimpleCryptTest {

    @Test
    void testEncryptDecryptWithString() throws Exception {
        String value = "secret";

        String encrypted = SimpleCrypt.encrypt(value);

        Assertions.assertNotEquals(value, encrypted);

        String decrypted = SimpleCrypt.decryptToString(encrypted);

        Assertions.assertEquals(value, decrypted);
    }

    @Test
    void testEncryptDecryptWithChars() throws Exception {
        String value = "secretäöüß";

        char[] chars = ByteUtils.toCharArray(value.getBytes(StandardCharsets.UTF_8));

        String encrypted = SimpleCrypt.encrypt(chars);

        Assertions.assertNotEquals(value, encrypted);

        char[] decryptedChars = SimpleCrypt.decryptToChars(encrypted);

        Assertions.assertArrayEquals(chars, decryptedChars);
    }

    /**
     * Test of isEncryptedValue method, of class SimpleCrypt.
     */
    @Test
    void testIsEncryptedValue() {
        Assertions.assertTrue(SimpleCrypt.isEncryptedValue("{abc}"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("abc}"));
    }

    @Test
    void testDecrypt1() {
        Exception ex = Assertions.assertThrows(GeneralSecurityException.class, ()->SimpleCrypt.decrypt("this isn't a encapsulated value"));
        Assertions.assertTrue(ex.getMessage().contains("This value is not with curly brackets"));
    }

}
