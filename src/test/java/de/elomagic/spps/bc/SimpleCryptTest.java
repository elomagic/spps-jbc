package de.elomagic.spps.bc;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Properties;

class SimpleCryptTest {

    private static final String PRIVATE_KEY_FILENAME = "settings";
    private static final Path PRIVATE_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", PRIVATE_KEY_FILENAME);

    private static String backup;

    @BeforeAll
    static void beforeAll() throws Exception {
        if (Files.exists(PRIVATE_KEY_FILE)) {
            backup = FileUtils.readFileToString(PRIVATE_KEY_FILE.toFile(), StandardCharsets.UTF_8);
        }

        Files.deleteIfExists(PRIVATE_KEY_FILE);
    }

    @AfterAll
    static void afterAll() throws Exception {
        Files.deleteIfExists(PRIVATE_KEY_FILE);

        if (backup != null) {
            FileUtils.write(PRIVATE_KEY_FILE.toFile(), backup, StandardCharsets.UTF_8);
        }
    }

    @Test
    void testCreatePrivateKey() throws Exception {
        Files.deleteIfExists(PRIVATE_KEY_FILE);
        Assertions.assertTrue(Files.notExists(PRIVATE_KEY_FILE));

        SimpleCrypt.createPrivateKey(true);

        Properties p = new Properties();
        try (Reader reader = Files.newBufferedReader(PRIVATE_KEY_FILE)) {
            p.load(reader);
        }

        Assertions.assertEquals(2, p.keySet().size());
    }

    @Test
    void testEncryptDecryptWithString() throws Exception {
        SimpleCrypt.createPrivateKey(true);

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
    void testRun() {
        Assertions.assertEquals(0, SimpleCrypt.run(new String[] {"abcde"}));
        Assertions.assertEquals(0, SimpleCrypt.run(null));
        Assertions.assertEquals(1, SimpleCrypt.run(new String[] {"-Secret"}));
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

    @Test
    void testSetSettingsFile() throws Exception {

        Path tempFolder = Files.createTempDirectory("tmpDirPrefix");
        Files.createDirectories(tempFolder);

        Path settingsFile =  tempFolder.resolve("alternativeSettings");
        Assertions.assertTrue(Files.notExists(settingsFile));

        String value = "secretäöüß";
        SimpleCrypt.createPrivateKey(true);
        String encrypted1 = SimpleCrypt.encrypt(value);
        Assertions.assertTrue(SimpleCrypt.isEncryptedValue(encrypted1));
        Assertions.assertEquals(value, SimpleCrypt.decryptToString(encrypted1));

        SimpleCrypt.setSettingsFile(settingsFile);
        Assertions.assertThrows(GeneralSecurityException.class, () -> SimpleCrypt.decrypt(encrypted1));

        SimpleCrypt.createPrivateKey(true);
        Assertions.assertTrue(Files.exists(settingsFile));

        String encrypted2 = SimpleCrypt.encrypt(value);
        SimpleCrypt.setSettingsFile(null);
        Assertions.assertThrows(GeneralSecurityException.class, () -> SimpleCrypt.decrypt(encrypted2));
    }

}
