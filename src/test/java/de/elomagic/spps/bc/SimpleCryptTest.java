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
        Assertions.assertEquals(54, encrypted.length());

        String decrypted = SimpleCrypt.decryptToString(encrypted);

        Assertions.assertEquals(value, decrypted);

        String e1 = SimpleCrypt.encrypt(value);
        String e2 = SimpleCrypt.encrypt(value);
        Assertions.assertNotEquals(e1, e2);

        Assertions.assertThrows(GeneralSecurityException.class, () -> SimpleCrypt.decryptToString("{bullshit}"));
    }

    @Test
    void testEncryptDecryptWithChars() throws Exception {
        String value = "secretäöüß";

        char[] chars = ByteUtils.toCharArray(value.getBytes(StandardCharsets.UTF_8));

        String encrypted = SimpleCrypt.encrypt(chars);

        Assertions.assertNotEquals(value, encrypted);

        char[] decryptedChars = SimpleCrypt.decryptToChars(encrypted);

        Assertions.assertArrayEquals(chars, decryptedChars);

        Assertions.assertNull(SimpleCrypt.encrypt((String)null));
        Assertions.assertNull(SimpleCrypt.encrypt((byte[])null));
        Assertions.assertNull(SimpleCrypt.decryptToString(null));
        Assertions.assertNull(SimpleCrypt.decrypt(null));
    }

    @Test
    void testMain() {
        Assertions.assertDoesNotThrow(() -> SimpleCrypt.main(new String[] {"abcde"}));
        Assertions.assertDoesNotThrow(() -> SimpleCrypt.main(null));
    }

    @Test
    void testIsEncryptedValue() {
        Assertions.assertTrue(SimpleCrypt.isEncryptedValue("{abc}"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("abc}"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("{abc"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue("abc"));
        Assertions.assertFalse(SimpleCrypt.isEncryptedValue(null));
    }

    @Test
    void testDecrypt1() {
        Exception ex = Assertions.assertThrows(GeneralSecurityException.class, ()->SimpleCrypt.decrypt("this isn't a encapsulated value"));
        Assertions.assertTrue(ex.getMessage().contains("This value is not with curly brackets"));
    }

}
