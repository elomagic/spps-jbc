package de.elomagic.spps.bc;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Properties;

class SimpleCryptTest {

    private static final String PRIVATE_KEY_FILENAME = "settings";
    private static final Path PRIVATE_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", PRIVATE_KEY_FILENAME);

    private static String backup;

    private Path createEmptyTempFile() throws IOException {
        Path file = File.createTempFile("SimpleCryptTest-", ".tmp").toPath();
        file.toFile().deleteOnExit();

        return file;
    }

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
    void testInit() throws Exception {
        Path file = createEmptyTempFile();
        SimpleCrypt.setSettingsFile(file);
        Files.deleteIfExists(file);

        Assertions.assertFalse(SimpleCrypt.isInitialize());

        Assertions.assertTrue(SimpleCrypt.init());

        Assertions.assertTrue(SimpleCrypt.isInitialize());

        Assertions.assertFalse(SimpleCrypt.init());
    }

    @Test
    void testCreatePrivateKey() throws Exception {
        Path file = createEmptyTempFile();

        Assertions.assertEquals(1, SimpleCrypt.run(new String[]{"-CreatePrivateKey", "-File", file.toString()}));

        Assertions.assertEquals(0, SimpleCrypt.run(new String[]{"-CreatePrivateKey", "-Force", "-File", file.toString()}));

        Properties p = new Properties();
        try (Reader reader = Files.newBufferedReader(file)) {
            p.load(reader);
        }

        Assertions.assertEquals(2, p.keySet().size());
    }

    @Test
    void testEncryptDecryptWithString() throws Exception {
        Path file = createEmptyTempFile();
        SimpleCrypt.createPrivateKey(file, null,true);
        SimpleCrypt.setSettingsFile(file);

        String value = "secret";

        String encrypted = SimpleCrypt.encrypt(value);

        Assertions.assertNotEquals(value, encrypted);
        Assertions.assertEquals(54, encrypted.length());

        String decrypted = SimpleCrypt.decryptToString(encrypted);

        Assertions.assertEquals(value, decrypted);

        String e1 = SimpleCrypt.encrypt(value);
        String e2 = SimpleCrypt.encrypt(value);
        Assertions.assertNotEquals(e1, e2);

        Assertions.assertThrows(SimpleCryptException.class, () -> SimpleCrypt.decryptToString("{bullshit}"));
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
        Assertions.assertEquals("NOT_NULL", SimpleCrypt.decryptToString("NOT_NULL"));
        Assertions.assertEquals("", SimpleCrypt.decryptToString(""));
        Assertions.assertNull(SimpleCrypt.decrypt(null));
        Assertions.assertThrows(SimpleCryptException.class, ()->SimpleCrypt.decrypt("{fake}"));
    }

    @Test
    void testSetSettingsFile() throws Exception {
        String value = "secretäöüß";
        Path file1 = createEmptyTempFile();
        SimpleCrypt.createPrivateKey(file1, null, true);
        SimpleCrypt.setSettingsFile(file1);
        String encrypted1 = SimpleCrypt.encrypt(value);
        Assertions.assertTrue(SimpleCrypt.isEncryptedValue(encrypted1));
        Assertions.assertEquals(value, SimpleCrypt.decryptToString(encrypted1));

        Path file2 = createEmptyTempFile();
        SimpleCrypt.setSettingsFile(file2);
        Assertions.assertThrows(SimpleCryptException.class, () -> SimpleCrypt.decrypt(encrypted1));

        SimpleCrypt.createPrivateKey(file2, null,true);
        Assertions.assertTrue(Files.exists(file2));

        String encrypted2 = SimpleCrypt.encrypt(value);
        SimpleCrypt.setSettingsFile(null);
        Assertions.assertThrows(SimpleCryptException.class, () -> SimpleCrypt.decrypt(encrypted2));
    }

    @Test
    void testGetArgument() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> SimpleCrypt.getArgument(Collections.emptyList(), null));
        Assertions.assertThrows(IllegalArgumentException.class, () -> SimpleCrypt.getArgument(Collections.emptyList(), "test"));
        Assertions.assertThrows(IllegalArgumentException.class, () -> SimpleCrypt.getArgument(Arrays.asList("test"), "test"));
        Assertions.assertEquals("value", SimpleCrypt.getArgument(Arrays.asList("test", "value"), "test"));
    }

}
