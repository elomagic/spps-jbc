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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;

/**
 * Simple crypt tool class by using BouncyCastle framework.
 */
public class SimpleCrypt {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final Logger LOGGER = LogManager.getLogger(SimpleCrypt.class);
    private static final Path MASTER_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", "masterkey");

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
        cipher.init(opmode, getMasterKey(), iv);

        return cipher;
    }

    @NotNull
    private static Key getMasterKey() throws GeneralSecurityException {
        try {
            if (!MASTER_KEY_FILE.getParent().toFile().exists()) {
                Files.createDirectories(MASTER_KEY_FILE.getParent());
            }

            byte[] result;
            SecretKey key;

            if (Files.exists(MASTER_KEY_FILE)) {
                byte[] base64 = Files.readAllBytes(MASTER_KEY_FILE);
                result = Base64.decode(base64);

                key = new SecretKeySpec(result, ALGORITHM);
            } else {
                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(256);
                key = kg.generateKey();

                result = key.getEncoded();

                String base64 = Base64.toBase64String(result);

                Files.write(MASTER_KEY_FILE, Collections.singleton(base64), StandardOpenOption.CREATE_NEW);
            }

            return key;
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to read master key", ex);
        } catch (NoSuchAlgorithmException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to acquire AES algorithm. This is required to function.", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to create or read master key.", ex);
        }
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
