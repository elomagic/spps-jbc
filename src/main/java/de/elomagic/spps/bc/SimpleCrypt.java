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
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Simple crypt tool class by using BouncyCastle framework.
 */
public final class SimpleCrypt {

    private static final Logger LOGGER = LogManager.getLogger(SimpleCrypt.class);
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String KEY_KEY = "key";
    private static final String RELOCATION_KEY = "relocation";
    private static final int PRIVATE_KEY_SIZE = 256;
    private static final Path DEFAULT_SETTINGS_FILE = Paths.get(System.getProperty("user.home"), ".spps", "settings");
    private static final AtomicReference<Path> SETTINGS_FILE = new AtomicReference<>(DEFAULT_SETTINGS_FILE);

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
        byte[] iv = new byte[PRIVATE_KEY_SIZE / 16];
        random.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Read private key from default location.
     *
     * @return Returns the private key.
     * @throws SimpleCryptException Thrown when unable to create private key
     */
    @NotNull
    private static Key readPrivateKey() throws SimpleCryptException {
        return readPrivateKey(SETTINGS_FILE.get());
    }

    /**
     * Read a private key file.
     *
     * @param file File of the private key. When relocation in file is set then key will be read from there.
     * @return Returns the private key.
     * @throws SimpleCryptException Thrown when unable to create private key
     */
    @NotNull
    private static Key readPrivateKey(@NotNull Path file) throws SimpleCryptException {
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
                    String key = p.getProperty(KEY_KEY, "");
                    if ("".equals(key)) {
                        throw new SimpleCryptException("No private key set.");
                    }
                    byte[] result = Base64.decode(key);
                    return new SecretKeySpec(result, ALGORITHM);
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new SimpleCryptException("Unable to read private key.", ex);
        }
    }

    /**
     * Creates a private key file.
     *
     * @param file File where the private key will be stored. If null then default file, which be stored in the user folder, will be used.
     * @param relocationFile Alternative file where to write file with private key
     * @param force When true and private key file already exists then it will be overwritten otherwise an exception will be thrown
     * @throws SimpleCryptException Thrown when unable to create private key
     */
    static void createPrivateKey(@Nullable Path file, @Nullable Path relocationFile, boolean force) throws SimpleCryptException {
        try {
            file = file == null ? SETTINGS_FILE.get() : file;

            if (Files.notExists(file.getParent())) {
                Files.createDirectories(file.getParent());
            }

            if (Files.exists(file) && !force) {
                throw new FileAlreadyExistsException("Private key file \"" + file+ "\" already exists. Use parameter \"-Force\" to overwrite it.");
            }

            Properties p = new Properties();

            if (relocationFile == null || file.equals(relocationFile)) {
                KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
                kg.init(PRIVATE_KEY_SIZE);
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

            LOGGER.info("Creating settings file");

            try (Writer writer = Files.newBufferedWriter(file, StandardCharsets.UTF_8)) {
                p.store(writer, "SPPS Settings");
            }
        } catch (IOException ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new IllegalStateException("Unable to create private key", ex);
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new SimpleCryptException("Unable to create or read private key.", ex);
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
    private static Cipher createCypher(int opmode, @NotNull IvParameterSpec iv) throws SimpleCryptException {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION, new BouncyCastleProvider());
            cipher.init(opmode, readPrivateKey(), iv);

            return cipher;
        } catch (Exception ex) {
            throw new SimpleCryptException(ex.getMessage(), ex);
        }
    }

    /**
     * Checks if settings file exists.
     *
     * Settings file can be "${user.home}/.spps/settings" or an alternative file which set with {@link SimpleCrypt#setSettingsFile(Path)}
     *
     * @return Returns true if exists.
     */
    static boolean isInitialize() {
        return Files.exists(SETTINGS_FILE.get());
    }

    /**
     * Initialize SimpleCrypt by checking of setting file.
     * <p>
     * Settings file can be "${user.home}/.spps/settings" or an alternative file which set with {@link SimpleCrypt#setSettingsFile(Path)}
     *
     * @throws SimpleCryptException Thrown when unable to create private key file
     * @return Returns true when settings file was created and false when settings file already exist.
     */
    public static boolean init() throws SimpleCryptException {
        if (!isInitialize()) {
            createPrivateKey(null, null, false);
            return true;
        }

        return false;
    }

    /**
     * Encrypt, encoded as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted byte array
     * @return Returns an encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws SimpleCryptException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(byte[] decrypted) throws SimpleCryptException {
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
            throw new SimpleCryptException(ex.getMessage(), ex);
        }
    }

    /**
     * Encrypt, encode as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted char array
     * @return Returns an encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws SimpleCryptException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(char[] decrypted) throws SimpleCryptException {
        return decrypted == null ? null : encrypt(CharUtils.toByteArray(decrypted));
    }

    /**
     * Encrypt, encode as Base64 and encapsulate with curly bracket of a string.
     *
     * @param decrypted a non encrypted string
     * @return Returns an encrypted, Base64 encoded string, surrounded with curly brackets.
     * @throws SimpleCryptException Thrown when an error occurred during encrypting.
     */
    @Nullable
    public static String encrypt(@Nullable String decrypted) throws SimpleCryptException {
        return decrypted == null ? null : encrypt(decrypted.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws SimpleCryptException Thrown when unable to decrypt data .
     */
    @Nullable
    public static byte[] decrypt(@Nullable String encryptedBase64) throws SimpleCryptException {
        if(!isEncryptedValue(encryptedBase64)) {
            return encryptedBase64 == null ? null : encryptedBase64.getBytes(StandardCharsets.UTF_8);
        }

        try {
            byte[] encryptedBytes = Base64.decode(encryptedBase64.substring(1, encryptedBase64.length() - 1));

            // Next IDE warning can be ignored because we need the IV from the encrypted string and we don't want to generate a new one.
            IvParameterSpec iv = new IvParameterSpec(encryptedBytes, 0, 16);

            Cipher cipher = createCypher(Cipher.DECRYPT_MODE, iv);
            return cipher.doFinal(encryptedBytes, 16, encryptedBytes.length-16);
        } catch(Exception ex) {
            LOGGER.error(ex.getMessage(), ex);
            throw new SimpleCryptException("Unable to decrypt data.", ex);
        }
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as char array.
     * @throws SimpleCryptException Thrown when unable to decrypt data .
     */
    @Nullable
    public static char[] decryptToChars(@Nullable String encryptedBase64) throws SimpleCryptException {
        return encryptedBase64 == null ? null : ByteUtils.toCharArray(decrypt(encryptedBase64));
    }

    /**
     * Decrypt an encrypted, Base64 encoded data string.
     *
     * @param encryptedBase64 Base64 encoded data string, encapsulated with curly brackets.
     * @return The encrypted data as string.
     * @throws SimpleCryptException Thrown when unable to decrypt data .
     */
    @Nullable
    public static String decryptToString(@Nullable String encryptedBase64) throws SimpleCryptException {
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

    /**
     * Set an alternative default settings file instead of default "${user.home}/.spps/settings".
     *
     * An application can use this feature to prevent sharing of the private key with other applications.
     *
     * @param file Alternative settings file or null to use the default file.
     */
    public static void setSettingsFile(@Nullable Path file) {
        LOGGER.info("Changing default settings file to {}", SETTINGS_FILE.get());
        SETTINGS_FILE.set(file == null ? DEFAULT_SETTINGS_FILE : file);
    }

    private static PrintWriter out() {
        return System.console() == null ? new PrintWriter(System.out, true) : System.console().writer();
    }

    static String getArgument(@NotNull List<String> args, @NotNull String option) {
        int index = args.indexOf(option);

        if (index == -1 || args.size() <= index+1) {
            throw new IllegalArgumentException("Syntax error. Argument not found.");
        }

        return args.get(index+1);
    }

    static int run(@Nullable String[] args) {
        try {
            List<String> argList = args == null ? Collections.emptyList() : Arrays.asList(args);

            if (argList.contains("-Secret")) {
                byte[] secret = getArgument(argList, "-Secret").getBytes(StandardCharsets.UTF_8);
                out().println(encrypt(secret));
            } else if (argList.contains("-CreatePrivateKey")) {
                boolean force = argList.contains("-Force");
                Path relocationFile = argList.contains("-Relocation") ? Paths.get(getArgument(argList, "-Relocation")) : null;
                Path file = argList.contains("-File") ? Paths.get(getArgument(argList, "-File")) : null;
                createPrivateKey(file, relocationFile, force);
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
