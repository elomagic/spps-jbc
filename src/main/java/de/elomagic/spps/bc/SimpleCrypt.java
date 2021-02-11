/*
 * Simple Password Protection Solution with Bouncy Castle
 *
 * Copyright © 2021-present Carsten Rambow (spps.dev@elomagic.de)
 *
 * This file is part of Simple Password Protection Solution with Bouncy Castle.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.elomagic.spps.bc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.pqc.math.linearalgebra.CharUtils;
import org.bouncycastle.util.encoders.Base64;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Properties;

/**
 * Simple crypt tool class by using BouncyCastle framework.
 */
public class SimpleCrypt {

    private static final Logger LOGGER = LogManager.getLogger(SimpleCrypt.class);
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String MASTER_KEY_FILENAME = "masterkey";
    private static final String KEY_KEY = "key";
    private static final String RELOCATION_KEY = "relocation";
    private static final Path MASTER_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", MASTER_KEY_FILENAME);

    private SimpleCrypt() {
    }

    /**
     * Creates a new random initialization vector.
     *
     * @return Returns the initialization vector but never null
     */
    @NotNull
    private static IvParameterSpec createInitializationVector() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[16];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    @NotNull
    private static Key readMasterKey() throws GeneralSecurityException {
        return readMasterKey(MASTER_KEY_FILE);
    }

    @NotNull
    private static Key readMasterKey(@NotNull Path file) throws GeneralSecurityException {
        try {
            if (Files.notExists(file)) {
                throw new FileNotFoundException("Unable to find settings file. At first you have to create a master key.");
            }

            Properties p = new Properties();
            try (Reader reader = Files.newBufferedReader(file)) {
                p.load(reader);

                if (p.getProperty(RELOCATION_KEY, "").trim().length() != 0) {
                    return readMasterKey(Paths.get(p.getProperty(RELOCATION_KEY)));
                } else {
                    byte[] result = Base64.decode(p.getProperty(KEY_KEY));
                    return new SecretKeySpec(result, ALGORITHM);
                }
            }
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to read master key", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to create or read master key.", ex);
        }
    }

    /**
     * Creates a new master key.
     *
     * @param force Must true to confirm to overwrite existing master key.
     * @throws GeneralSecurityException Thrown when unable to create master key
     */
    public static void createMasterKey(boolean force) throws GeneralSecurityException {
        createMasterKey(MASTER_KEY_FILE, force);
    }

    private static void createMasterKey(@NotNull Path file, boolean force) throws GeneralSecurityException {
        if (MASTER_KEY_FILE.equals(file)) {
            createMasterKey(file, null, force);
        } else {
            createMasterKey(MASTER_KEY_FILE, file, force);
        }
    }

    private static void createMasterKey(@NotNull Path file, @Nullable Path relocationFile, boolean force) throws GeneralSecurityException {
        try {
            if (!MASTER_KEY_FILE.getParent().toFile().exists()) {
                Files.createDirectories(MASTER_KEY_FILE.getParent());
            }

            if (Files.exists(file) && !force) {
                throw new FileAlreadyExistsException("Master key file \"" + file+ "\" already exists. Use parameter \"-Force\" to overwrite it.");
            }

            Properties p = new Properties();

            if (relocationFile == null || file.equals(relocationFile)) {
                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(256);
                SecretKey key = kg.generateKey();

                byte[] result = key.getEncoded();

                String base64 = Base64.toBase64String(result);


                p.put(KEY_KEY, base64);
                p.put(RELOCATION_KEY, "");
            } else {
                p.put(KEY_KEY, "");
                p.put(RELOCATION_KEY, relocationFile.toString());
                createMasterKey(relocationFile, null, force);
            }

            try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                p.store(writer, "SPPS Settings");
            }
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to create master key", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to create or read master key.", ex);
        }
    }

    /**
     * Creates a cipher.
     *
     * @param opmode The operation mode of this cipher (this is one of the following: {@code ENCRYPT_MODE} or {@code DECRYPT_MODE}
     * @param iv Initialization vector for first block
     * @return Returns cipher
     */
    @NotNull
    private static Cipher createCypher(int opmode, @NotNull IvParameterSpec iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, new BouncyCastleProvider());
        cipher.init(opmode, readMasterKey(), iv);

        return cipher;
    }

    /**
     * Encrypt, encoded as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted byte array
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable byte[] decrypted) throws GeneralSecurityException {
        if (decrypted == null) {
            return null;
        }

        try {
            IvParameterSpec iv = createInitializationVector();
            Cipher cipher = createCypher(Cipher.ENCRYPT_MODE, iv);
            byte[] encrypted = cipher.doFinal(decrypted);

            byte[] data = new byte[iv.getIV().length + encrypted.length];
            System.arraycopy(iv.getIV(), 0, data, 0, iv.getIV().length);
            System.arraycopy(encrypted, 0, data, iv.getIV().length, encrypted.length);

            return "{" + Base64.toBase64String(data) + "}";
        } catch(Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }

    /**
     * Encrypt, encode as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted char array
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable char[] decrypted) throws GeneralSecurityException {
        return decrypted == null ? null : encrypt(CharUtils.toByteArray(decrypted));
    }

    /**
     * Encrypt, encode as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted string
     * @return Returns a encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws GeneralSecurityException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable String decrypted) throws GeneralSecurityException {
        return decrypted == null ? null : encrypt(decrypted.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static byte[] decrypt(@Nullable String encryptedBase64) throws GeneralSecurityException {
        if (encryptedBase64 == null) {
            return null;
        }

        if(!isEncryptedValue(encryptedBase64)) {
            throw new GeneralSecurityException("This value is not with curly brackets encapsulated as an encrypted value. Unable to decrypt.");
        }

        try {
            byte[] encryptedBytes = Base64.decode(encryptedBase64.substring(1, encryptedBase64.length() - 1));

            IvParameterSpec iv = new IvParameterSpec(encryptedBytes, 0, 16);

            Cipher cipher = createCypher(Cipher.DECRYPT_MODE, iv);
            return cipher.doFinal(encryptedBytes, 16, encryptedBytes.length-16);
        } catch(Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to decrypt data.", ex);
        }
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as char array.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static char[] decryptToChars(@Nullable String encryptedBase64) throws GeneralSecurityException {
        return encryptedBase64 == null ? null : ByteUtils.toCharArray(decrypt(encryptedBase64));
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws GeneralSecurityException Thrown when unable to decrypt data .
     */
    @Nullable
    public static String decryptToString(@Nullable String encryptedBase64) throws GeneralSecurityException {
        return encryptedBase64 == null ? null : new String(decrypt(encryptedBase64), StandardCharsets.UTF_8);
    }

    /**
     * Returns true when value is encrypted, tagged by surrounding braces "{" and "}".
     *
     * @param value Value to be checked
     * @return Returns true when value is identified as an encrypted value.
     */
    public static boolean isEncryptedValue(@Nullable String value) {
        return value != null && value.startsWith("{") && value.endsWith("}");
    }

    /**
     * Tooling method for simple and fast encrypting secrets.
     *
     * @param args First argument must contain value to encrypt
     */
    public static void main(String[] args) {
        try {
            if (args == null || args.length == 0) {
                LOGGER.error("No value found to encrypt.");
                return;
            }

            String s = encrypt(args[0]);

            LOGGER.info("Encrypted value: {}", s);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
        }
    }

}
