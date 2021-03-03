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
import org.apache.logging.log4j.core.util.IOUtils;
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
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Properties;

/**
 * Simple crypt tool class by using BouncyCastle framework.
 */
public class SimpleCrypt {

    private static final Logger LOGGER = LogManager.getLogger(SimpleCrypt.class);
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String PRIVATE_KEY_FILENAME = "settings";
    private static final String KEY_KEY = "key";
    private static final String RELOCATION_KEY = "relocation";
    private static final Path PRIVATE_KEY_FILE = Paths.get(System.getProperty("user.home"), ".spps", PRIVATE_KEY_FILENAME);

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
     * Read private key from default location.
     *
     * @return Returns the private key.
     * @throws GeneralSecurityException Thrown when unable to create private key
     */
    @NotNull
    private static Key readPrivateKey() throws GeneralSecurityException {
        return readPrivateKey(PRIVATE_KEY_FILE);
    }

    /**
     * Read a private key.
     *
     * @param file File of the private key. When relocation in file is set then key will be read from there.
     * @return Returns the private key.
     * @throws GeneralSecurityException Thrown when unable to create private key
     */
    @NotNull
    private static Key readPrivateKey(@NotNull Path file) throws GeneralSecurityException {
        try {
            if (Files.notExists(file)) {
                throw new FileNotFoundException("Unable to find settings file. At first you have to create a private key.");
            }

            Properties p = new Properties();
            try (Reader reader = Files.newBufferedReader(file)) {
                p.load(reader);

                if (p.getProperty(RELOCATION_KEY, "").trim().length() != 0) {
                    return readPrivateKey(Paths.get(p.getProperty(RELOCATION_KEY)));
                } else {
                    byte[] result = Base64.decode(p.getProperty(KEY_KEY));
                    return new SecretKeySpec(result, ALGORITHM);
                }
            }
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to read private key", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to create or read private key.", ex);
        }
    }

    /**
     * Creates a new private key.
     *
     * @param force Must true to confirm to overwrite existing private key.
     * @throws GeneralSecurityException Thrown when unable to create private key
     */
    public static void createPrivateKey(boolean force) throws GeneralSecurityException {
        createPrivateKey(PRIVATE_KEY_FILE, force);
    }

    /**
     * Creates a private key file.
     *
     * @param file (Alternative) file where to write file with private key
     * @param force When true and private key file already exists then it will be overwritten otherwise an exception will be thrown
     * @throws GeneralSecurityException Thrown when unable to create private key
     */
    private static void createPrivateKey(@NotNull Path file, boolean force) throws GeneralSecurityException {
        if (PRIVATE_KEY_FILE.equals(file)) {
            createPrivateKey(file, null, force);
        } else {
            createPrivateKey(PRIVATE_KEY_FILE, file, force);
        }
    }

    /**
     * Creates a private key file.
     *
     * @param file Private key file
     * @param relocationFile Alternative file where to write file with private key
     * @param force When true and private key file already exists then it will be overwritten otherwise an exception will be thrown
     * @throws GeneralSecurityException Thrown when unable to create private key
     */
    private static void createPrivateKey(@NotNull Path file, @Nullable Path relocationFile, boolean force) throws GeneralSecurityException {
        try {
            if (!PRIVATE_KEY_FILE.getParent().toFile().exists()) {
                Files.createDirectories(PRIVATE_KEY_FILE.getParent());
            }

            if (Files.exists(file) && !force) {
                throw new FileAlreadyExistsException("Private key file \"" + file+ "\" already exists. Use parameter \"-Force\" to overwrite it.");
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
                createPrivateKey(relocationFile, null, force);
            }

            try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                p.store(writer, "SPPS Settings");
            }
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to create private key", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new GeneralSecurityException("Unable to create or read private key.", ex);
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
        cipher.init(opmode, readPrivateKey(), iv);

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
        // For JUnit test we have to use System.out because console() will return null
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

    private static PrintWriter out() {
        return System.console() == null ? new PrintWriter(System.out, true) : System.console().writer();
    }

    private static String getArgument(@Nullable String[] args, int index) {
        if (args == null || args.length <= index) {
            throw new IllegalArgumentException("Syntax error. Argument not found.");
        }

        return args[index];
    }

    static int run(@Nullable String[] args) {
        try {
            args = args == null ? new String[0] : args;

            if (Arrays.binarySearch(args, "-Secret") != -1) {
                int i = Arrays.binarySearch(args, "-Secret");
                byte[] secret = getArgument(args, i+1).getBytes(StandardCharsets.UTF_8);
                out().println(encrypt(secret));
            } else if (Arrays.binarySearch(args, "-CreatePrivateKey") != -1) {
                boolean force = Arrays.binarySearch(args, "-Force") != -1;
                int i = Arrays.binarySearch(args, "-Relocation");
                Path relocation = i == -1 ? null : Paths.get(getArgument(args, i+1));
                if (relocation == null) {
                    createPrivateKey(force);
                } else {
                    createPrivateKey(relocation, force);
                }
            } else {
                String resource = "/" + SimpleCrypt.class.getPackage().getName().replace(".", "/") + "/Help.txt";
                try (InputStream in = SimpleCrypt.class.getResourceAsStream(resource); InputStreamReader reader = new InputStreamReader(in)) {
                    String text = IOUtils.toString(reader);
                    out().println(text);
                }
            }
            return 0;
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            return 1;
        }
    }

    /**
     * Tooling method for simple and fast encrypting secrets.
     *
     * @param args First argument must contain value to encrypt
     */
    public static void main(@Nullable String[] args) {
        int exitCode = run(args);
        System.exit(exitCode);
    }

}
