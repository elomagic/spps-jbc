package de.elomagic.spps.bc;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Properties;

class SimpleCryptTest {

    private static final String MASTER_KEY_FILENAME = "masterkey";
    private static final Path MASTER_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", MASTER_KEY_FILENAME);

    private static Properties backup;

    @BeforeAll
    static void beforeAll() throws Exception {
        if (Files.exists(MASTER_KEY_FILE)) {
            try (Reader reader = Files.newBufferedReader(MASTER_KEY_FILE)) {
                backup = new Properties();
                backup.load(reader);
            }
        }

        Files.deleteIfExists(MASTER_KEY_FILE);
    }

    @AfterAll
    static void afterAll() throws Exception {
        Files.deleteIfExists(MASTER_KEY_FILE);

        if (backup != null) {
            try (Writer writer = Files.newBufferedWriter(MASTER_KEY_FILE, StandardCharsets.UTF_8)) {
                backup.store(writer, "SPPS Settings");
            }
        }
    }

    @Test
    void testCreateMasterKey() throws Exception {
        Assertions.assertTrue(Files.notExists(MASTER_KEY_FILE));

        SimpleCrypt.createMasterKey(true);

        Properties p = new Properties();
        try (Reader reader = Files.newBufferedReader(MASTER_KEY_FILE)) {
            p.load(reader);
        }

        Assertions.assertEquals(2, p.keySet().size());
    }

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
